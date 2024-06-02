#include <archive.h>
#include <archive_entry.h>
#include <brotli/decode.h>
#include <fcntl.h>
#include <lz4frame.h>
#include <lzma.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <zstd.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <initializer_list>
#include <mntent.h>
#include <mutex>
#include <queue>
#include <sstream>
#include <string>
#include <sys/mount.h>
#include <sys/system_properties.h>
#include <thread>
#include <utility>
#include <vector>

#define MEMORY_LIMIT_PER_THREAD 128 * 1024 * 1024

using namespace std;
using mapped = vector<vector<string>>;
static FILE *outfd;
string result_value;
string zip_filename;
bool notify_flash = false;
bool quick_flash = false;
size_t totalBytes = 0;
mutex print_mtx;

class ThreadManager {
public:
  ThreadManager()
      : max_threads((thread::hardware_concurrency() > 0 &&
                     thread::hardware_concurrency() % 2 == 0)
                        ? thread::hardware_concurrency() / 2
                        : 1) {}

  ~ThreadManager() {
    for (auto &thread : threads) {
      if (thread.joinable()) {
        thread.join();
      }
    }
  }

  template <typename... Args> void addThread(Args &&...args) {
    function<void()> threadFunc = bind(std::forward<Args>(args)...);
    unique_lock<mutex> lock(mutex_);
    threads.push_back(thread([this, threadFunc]() {
      threadFunc();
      {
        unique_lock<mutex> lock(mutex_);
        running_threads--;
        cv.notify_one();
      }
    }));
    running_threads++;
    if (running_threads >= max_threads) {
      cv.wait(lock, [this] { return running_threads < max_threads; });
    }
  }

  void waitAll() {
    unique_lock<mutex> lock(mutex_);
    cv.wait(lock, [this] { return running_threads == 0; });
  }

private:
  vector<thread> threads;
  mutex mutex_;
  condition_variable cv;
  int max_threads;
  int running_threads = 0;
};

void ui_print(const char *string, ...) {
  va_list args;
  va_start(args, string);

  {
    lock_guard<mutex> lock(print_mtx);
    fprintf(outfd, "ui_print ");
    vfprintf(outfd, string, args);
    fprintf(outfd, "\n");
    fprintf(outfd, "ui_print\n");

    fflush(outfd);
  }

  va_end(args);
}

void add_progress(size_t bytes) {
  if (totalBytes <= 0) {
    return;
  }
  float percentage = static_cast<float>(((double)bytes / (double)totalBytes));

  {
    lock_guard<mutex> lock(print_mtx);
    fprintf(outfd, "progress %.64f 0\n", percentage);
    fprintf(outfd, "set_progress 1.000000\n");

    fflush(outfd);
  }
}

bool isDelimiter(char c, const string &delimiters) {
  return delimiters.find(c) != string::npos;
}

vector<string> splitByDelimiters(const string &str) {
  vector<string> segments;
  string segment;
  istringstream tokenStream(str);
  const string delimiters = " =:";

  char c;
  while (tokenStream >> noskipws >> c) {
    if (isDelimiter(c, delimiters)) {
      if (!segment.empty()) {
        segments.push_back(segment);
        segment.clear();
      }
    } else {
      segment += c;
    }
  }
  if (!segment.empty()) {
    segments.push_back(segment);
  }

  return segments;
}

vector<string> processSimpleCommand(const string &input) {
  vector<string> result;
  string prefix = splitByDelimiters(input)[0];

  result.push_back(prefix);
  result.push_back(input.substr(prefix.size() + 1));

  return result;
}

static void property_callback(const prop_info *pi, void *cookie) {
  string *result = static_cast<string *>(cookie);
  char value[PROP_VALUE_MAX];
  __system_property_read(pi, nullptr, value);
  *result = value;
}

string GetProperty(const string &prop) {
  string result;
  const prop_info *pi = __system_property_find(prop.c_str());
  if (pi != nullptr) {
    property_callback(pi, &result);
  }
  return result;
}

string getRealPath(const string &symbolicLinkPath) {
  char resolvedPath[PATH_MAX];
  if (realpath(symbolicLinkPath.c_str(), resolvedPath) != nullptr) {
    return string(resolvedPath);
  } else {
    return "NULL";
  }
}

void umount_device(string &device) {
  FILE *mountFile = setmntent("/proc/mounts", "r");
  if (mountFile == nullptr) {
    return;
  }

  struct mntent *entry;
  while ((entry = getmntent(mountFile)) != nullptr) {
    if (strcmp(entry->mnt_fsname, device.c_str()) == 0 ||
        strcmp(entry->mnt_fsname, getRealPath(device).c_str())) {
      umount(entry->mnt_dir);
    }
  }

  endmntent(mountFile);
}

class BrotliHyperFlash {
private:
  size_t const brotliBufferSize = 128 * 1024;
  atomic<size_t> usedRAM{0};
  queue<pair<size_t, vector<unsigned char>>> buffers_first;
  queue<pair<size_t, vector<unsigned char>>> buffers_second;
  mutex mtx_first;
  mutex mtx_second;
  atomic<bool> unzip_finished{false};
  atomic<bool> brotli_finished{false};
  atomic<bool> write_finished{false};
  atomic<bool> emergency_end{false};
  atomic<bool> unzip_running{true};
  condition_variable do_brotli;
  condition_variable do_write;
  condition_variable ram_continue;
  mutex mtx_brotli;
  mutex mtx_write;
  mutex ram_lock;
  pair<string, string> flash_data;

public:
  BrotliHyperFlash(pair<string, string> d) : flash_data(d) {}

  void unzip() {
    struct archive *a = archive_read_new();
    archive_read_support_format_zip(a);

    if (archive_read_open_filename(a, zip_filename.c_str(), 10240)) {
      ui_print("Failed to open archive: %zu", archive_error_string(a));
      emergency_end.store(true, memory_order_relaxed);
      do_brotli.notify_one();
      archive_read_free(a);
      return;
    }

    vector<unsigned char> compressedBuffer(brotliBufferSize);

    size_t read;
    bool found = false;
    struct archive_entry *entry;
    while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
      const char *filename = archive_entry_pathname(entry);
      if (strcmp(filename, flash_data.first.c_str()) == 0) {
        found = true;
        while ((read = archive_read_data(a, compressedBuffer.data(),
                                         brotliBufferSize)) > 0 &&
               !emergency_end.load(memory_order_relaxed)) {

          // Guard push -> notify
          {
            lock_guard<mutex> lock(mtx_first);
            buffers_first.push(make_pair(read, compressedBuffer));
          }
          do_brotli.notify_one();

          // Increment used ram and check if it exceeds limit.
          usedRAM += read;
          if (usedRAM.load(memory_order_relaxed) >= MEMORY_LIMIT_PER_THREAD) {
            unzip_running.store(false, memory_order_relaxed);
            unique_lock<mutex> ram(ram_lock);
            ram_continue.wait(ram);
            unzip_running.store(true, memory_order_relaxed);
          }
        }

        break;
      }
    }

    unzip_finished.store(true, memory_order_relaxed);
    archive_read_close(a);
    archive_read_free(a);

    if (!found) {
      ui_print("Could not find %s on archive.", flash_data.first.c_str());
      emergency_end.store(true, memory_order_relaxed);
      do_brotli.notify_one();
    }
  }

  void brotlidec() {
    vector<unsigned char> decompressedBuffer(brotliBufferSize);

    // Brotli defaults
    BrotliDecoderResult result = BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT;
    size_t available_in = 0;
    const uint8_t *next_in = nullptr;
    size_t available_out = decompressedBuffer.size();
    uint8_t *next_out;

    BrotliDecoderState *decoder = BrotliDecoderCreateInstance(0, 0, 0);

    if (!decoder) {
      ui_print("Failed to initialize brotli decoder.");
      emergency_end.store(true, memory_order_relaxed);
      return;
    }

    BrotliDecoderSetParameter(decoder, BROTLI_DECODER_PARAM_LARGE_WINDOW, 1);

    while (!emergency_end.load(memory_order_relaxed)) {
      if (buffers_first.empty()) {
        if (unzip_finished.load(memory_order_relaxed)) {
          break;
        } else {
          unique_lock<mutex> brotli_lock(mtx_brotli);
          do_brotli.wait(brotli_lock);
          if (emergency_end.load(memory_order_relaxed)) {
            break; // Prevent from being stuck
          }
        }
      }

      // Lock -> read -> delete [0] -> unlock
      unique_lock<mutex> lock(mtx_first);
      auto front = buffers_first.front();
      buffers_first.pop();
      lock.unlock();

      available_in = front.first;
      next_in = front.second.data();
      available_out = decompressedBuffer.size();
      next_out = decompressedBuffer.data();

      while (true) {
        result =
            BrotliDecoderDecompressStream(decoder, &available_in, &next_in,
                                          &available_out, &next_out, nullptr);
        if (result == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT) {
          size_t write_size = decompressedBuffer.size() - available_out;
          {
            lock_guard<mutex> lock(mtx_second);
            buffers_second.push(make_pair(write_size, decompressedBuffer));
          }
          do_write.notify_one();

          usedRAM += write_size;

          available_out = decompressedBuffer.size();
          next_out = decompressedBuffer.data();
        } else if (result == BROTLI_DECODER_RESULT_ERROR) {
          ui_print(
              "Brotli decompression error: %s\n",
              BrotliDecoderErrorString(BrotliDecoderGetErrorCode(decoder)));
          emergency_end.store(true, memory_order_relaxed);
          goto end;
        } else {
          break;
        }
      }

      size_t produced = decompressedBuffer.size() - available_out;
      if (produced > 0) {
        {
          lock_guard<mutex> lock(mtx_second);
          buffers_second.push(make_pair(produced, decompressedBuffer));
        }
        do_write.notify_one();
        usedRAM += produced;
      }

      usedRAM -= front.first;
    }

  end:
    brotli_finished.store(true, memory_order_relaxed);
    do_write.notify_one();
    ram_continue.notify_one();
  }

  void writer() {
    int fd =
        open(flash_data.second.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0660);
    if (fd == -1) {
      ui_print("Failed to open %s!", flash_data.second.c_str());
      emergency_end.store(true, memory_order_relaxed);
      goto end;
    }

    while (!emergency_end.load(memory_order_relaxed)) {
      if (buffers_second.empty()) {
        if (brotli_finished.load(memory_order_relaxed)) {
          break;
        } else {
          unique_lock<mutex> write_lock(mtx_write);
          do_write.wait(write_lock);
          if (emergency_end.load(
                  memory_order_relaxed)) { // Maybe it was notified after a
                                           // failure.
            break;                         // Prevent from being stuck
          }
        }
      }

      unique_lock<mutex> lock(mtx_second);
      auto front = buffers_second.front();
      buffers_second.pop();
      lock.unlock();

      if (write(fd, front.second.data(), front.first) !=
          static_cast<ssize_t>(front.first)) {
        ui_print("Error writing data to %s!", flash_data.second.c_str());
        close(fd);
        emergency_end.store(true, memory_order_relaxed);
        goto end;
      }

      add_progress(front.first);
      usedRAM -= front.first;
      if (usedRAM.load(memory_order_relaxed) <= MEMORY_LIMIT_PER_THREAD / 2 &&
          !unzip_running.load(memory_order_relaxed)) {
        ram_continue.notify_one();
      }
    }
    close(fd);

  end:
    write_finished.store(true, memory_order_relaxed);
    if (notify_flash && !emergency_end.load(memory_order_relaxed)) {
      ui_print("%s - OK", flash_data.first.c_str());
    }
    ram_continue.notify_one();
  }
};

class LzmaHyperFlash {
private:
  size_t const lzmaBufferSize = 128 * 1024;
  atomic<size_t> usedRAM{0};
  queue<pair<size_t, vector<unsigned char>>> buffers_first;
  queue<pair<size_t, vector<unsigned char>>> buffers_second;
  mutex mtx_first;
  mutex mtx_second;
  atomic<bool> unzip_finished{false};
  atomic<bool> unlzma_finished{false};
  atomic<bool> write_finished{false};
  atomic<bool> emergency_end{false};
  atomic<bool> unzip_running{true};
  condition_variable do_lzma;
  condition_variable do_write;
  condition_variable ram_continue;
  mutex mtx_lzma;
  mutex mtx_write;
  mutex ram_lock;
  pair<string, string> flash_data;

public:
  LzmaHyperFlash(pair<string, string> d) : flash_data(d) {}

  void unzip() {
    struct archive *a = archive_read_new();
    archive_read_support_format_zip(a);

    if (archive_read_open_filename(a, zip_filename.c_str(), 10240)) {
      ui_print("Failed to open archive: %zu", archive_error_string(a));
      emergency_end.store(true, memory_order_relaxed);
      do_lzma.notify_one();
      archive_read_free(a);
      return;
    }

    vector<unsigned char> compressedBuffer(lzmaBufferSize);

    size_t read;
    bool found = false;
    struct archive_entry *entry;
    while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
      const char *filename = archive_entry_pathname(entry);
      if (strcmp(filename, flash_data.first.c_str()) == 0) {
        found = true;
        while ((read = archive_read_data(a, compressedBuffer.data(),
                                         lzmaBufferSize)) > 0 &&
               !emergency_end.load(memory_order_relaxed)) {

          // Guard push -> notify
          {
            lock_guard<mutex> lock(mtx_first);
            buffers_first.push(make_pair(read, compressedBuffer));
          }
          do_lzma.notify_one();

          // Increment used ram and check if it exceeds limit.
          usedRAM += read;
          if (usedRAM.load(memory_order_relaxed) >= MEMORY_LIMIT_PER_THREAD) {
            unzip_running.store(false, memory_order_relaxed);
            unique_lock<mutex> ram(ram_lock);
            ram_continue.wait(ram);
            unzip_running.store(true, memory_order_relaxed);
          }
        }

        break;
      }
    }

    unzip_finished.store(true, memory_order_relaxed);
    archive_read_close(a);
    archive_read_free(a);

    if (!found) {
      ui_print("Could not find %s on archive.", flash_data.first.c_str());
      emergency_end.store(true, memory_order_relaxed);
      do_lzma.notify_one();
    }
  }

  void unlzma() {
    // LZMA Stream
    lzma_stream strm = LZMA_STREAM_INIT;

    // Initialize decoder
    lzma_ret ret = lzma_stream_decoder(&strm, UINT64_MAX, 0);

    if (ret != LZMA_OK) {
      switch (ret) {
      case LZMA_MEM_ERROR:
        ui_print("LZMA: Memory allocation failed");
        break;
      case LZMA_OPTIONS_ERROR:
        ui_print("LZMA: Unsupported decompressor flags");
        break;
      default:
        ui_print("LZMA: Unknown error, possibly a bug");
        break;
      }

      emergency_end.store(true, memory_order_relaxed);
      lzma_end(&strm);
      return;
    }

    vector<unsigned char> decompressedBuffer(lzmaBufferSize);

    strm.next_in = NULL;
    strm.avail_in = 0;
    strm.next_out = decompressedBuffer.data();
    strm.avail_out = decompressedBuffer.size();

    while (!emergency_end.load(memory_order_relaxed)) {
      if (buffers_first.empty()) {
        if (unzip_finished.load(memory_order_relaxed)) {
          break;
        } else {
          unique_lock<mutex> lzma_lock(mtx_lzma);
          do_lzma.wait(lzma_lock);
          if (emergency_end.load(
                  memory_order_relaxed)) { // Maybe it was notified after a
                                           // failure.
            break;                         // Prevent from being stuck
          }
        }
      }

      // Lock -> read -> delete [0] -> unlock
      unique_lock<mutex> lock(mtx_first);
      auto front = buffers_first.front();
      buffers_first.pop();
      lock.unlock();

      strm.next_in = front.second.data();
      strm.avail_in = front.first;
      while (strm.avail_in > 0) {
        lzma_ret ret = lzma_code(&strm, LZMA_RUN);
        if (strm.avail_out == 0 || ret == LZMA_STREAM_END) {
          size_t write_size = decompressedBuffer.size() - strm.avail_out;

          // Guard push -> notify
          {
            lock_guard<mutex> lock(mtx_second);
            buffers_second.push(make_pair(write_size, decompressedBuffer));
          }
          do_write.notify_one();

          // Increment ram usage
          usedRAM += write_size;

          strm.next_out = decompressedBuffer.data();
          strm.avail_out = decompressedBuffer.size();
        }

        if (ret != LZMA_OK) {
          if (ret == LZMA_STREAM_END) {
            if (!unzip_finished.load(
                    memory_order_relaxed)) { // LZMA Finished but libarchive
                                             // still unpacking, warn about it.
              ui_print("LZMA: Unexpected stream end. Check %s integrity",
                       flash_data.first.c_str());
            }
            usedRAM -= front.first;
            goto end;
          }
          switch (ret) {
          case LZMA_MEM_ERROR:
            ui_print("LZMA: Memory allocation failed");
            break;
          case LZMA_OPTIONS_ERROR:
            ui_print("LZMA: Unsupported decompressor flags");
            break;
          default:
            ui_print("LZMA: Unknown error, possibly a bug (error code %zu)",
                     ret);
            break;
          }
          emergency_end.store(true, memory_order_relaxed);
          usedRAM -= front.first;
          goto end;
        }
      }
      usedRAM -= front.first;
    }

  end:
    unlzma_finished.store(true, memory_order_relaxed);
    lzma_end(&strm);
    do_write.notify_one();
    ram_continue.notify_one();
  }

  void writer() {
    int fd =
        open(flash_data.second.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0660);
    if (fd == -1) {
      ui_print("Failed to open %s!", flash_data.second.c_str());
      emergency_end.store(true, memory_order_relaxed);
      goto end;
    }

    while (!emergency_end.load(memory_order_relaxed)) {
      if (buffers_second.empty()) {
        if (unlzma_finished.load(memory_order_relaxed)) {
          break;
        } else {
          unique_lock<mutex> write_lock(mtx_write);
          do_write.wait(write_lock);
          if (emergency_end.load(
                  memory_order_relaxed)) { // Maybe it was notified after a
                                           // failure.
            break;                         // Prevent from being stuck
          }
        }
      }

      unique_lock<mutex> lock(mtx_second);
      auto front = buffers_second.front();
      buffers_second.pop();
      lock.unlock();

      if (write(fd, front.second.data(), front.first) !=
          static_cast<ssize_t>(front.first)) {
        ui_print("Error writing data to %s!", flash_data.second.c_str());
        close(fd);
        emergency_end.store(true, memory_order_relaxed);
        goto end;
      }

      add_progress(front.first);
      usedRAM -= front.first;
      if (usedRAM.load(memory_order_relaxed) <= MEMORY_LIMIT_PER_THREAD / 2 &&
          !unzip_running.load(memory_order_relaxed)) {
        ram_continue.notify_one();
      }
    }
    close(fd);

  end:
    write_finished.store(true, memory_order_relaxed);
    if (notify_flash && !emergency_end.load(memory_order_relaxed)) {
      ui_print("%s - OK", flash_data.first.c_str());
    }
    ram_continue.notify_one();
  }
};

class ZstdHyperFlash {
private:
  atomic<size_t> usedRAM{0};
  queue<pair<size_t, vector<unsigned char>>> buffers;
  mutex mtx;
  atomic<bool> unzip_finished{false};
  atomic<bool> unzstd_finished{false};
  atomic<bool> emergency_end{false};
  atomic<bool> unzip_running{true};
  condition_variable do_zstd;
  condition_variable ram_continue;
  mutex mtx_zstd;
  mutex ram_lock;
  pair<string, string> flash_data;

public:
  ZstdHyperFlash(pair<string, string> d) : flash_data(d) {}

  void unzip() {
    struct archive *a = archive_read_new();
    archive_read_support_format_zip(a);

    if (archive_read_open_filename(a, zip_filename.c_str(), 10240)) {
      ui_print("Failed to open archive: %zu", archive_error_string(a));
      emergency_end.store(true, memory_order_relaxed);
      do_zstd.notify_one();
      archive_read_free(a);
      return;
    }

    vector<unsigned char> compressedBuffer(ZSTD_DStreamInSize());

    size_t read;
    bool found = false;
    struct archive_entry *entry;
    while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
      const char *filename = archive_entry_pathname(entry);
      if (strcmp(filename, flash_data.first.c_str()) == 0) {
        found = true;
        while ((read = archive_read_data(a, compressedBuffer.data(),
                                         ZSTD_DStreamInSize())) > 0 &&
               !emergency_end.load(memory_order_relaxed)) {
          {
            lock_guard<mutex> lock(mtx);
            buffers.push(make_pair(read, compressedBuffer));
          }
          do_zstd.notify_one();

          usedRAM += read;
          if (usedRAM.load(memory_order_relaxed) >= MEMORY_LIMIT_PER_THREAD) {
            unzip_running.store(false, memory_order_relaxed);
            unique_lock<mutex> ram(ram_lock);
            ram_continue.wait(ram);
            unzip_running.store(true, memory_order_relaxed);
          }
        }

        break;
      }
    }

    unzip_finished.store(true, memory_order_relaxed);
    archive_read_close(a);
    archive_read_free(a);

    if (!found) {
      ui_print("Could not find %s on archive.", flash_data.first.c_str());
      emergency_end.store(true, memory_order_relaxed);
      do_zstd.notify_one();
    }
  }

  void unzstd() {
    ZSTD_DCtx *const dctx = ZSTD_createDCtx();
    if (dctx == nullptr) {
      ui_print("ZSTD_createDCtx() failed!");
      emergency_end.store(true, memory_order_relaxed);
      return;
    }

    int fd =
        open(flash_data.second.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0660);
    if (fd == -1) {
      ui_print("Failed to open %s!", flash_data.second.c_str());
      emergency_end.store(true, memory_order_relaxed);
      ZSTD_freeDCtx(dctx);
      return;
    }

    vector<unsigned char> decompressedBuffer(ZSTD_DStreamOutSize());

    while (!emergency_end.load(memory_order_relaxed)) {
      if (buffers.empty()) {
        if (unzip_finished.load(memory_order_relaxed)) {
          break;
        } else {
          unique_lock<mutex> zstd_lock(mtx_zstd);
          do_zstd.wait(zstd_lock);
          if (emergency_end.load(
                  memory_order_relaxed)) { // Maybe it was notified after a
                                           // failure.
            break;
          }
        }
      }

      unique_lock<mutex> lock(mtx);
      auto front = buffers.front();
      buffers.pop();
      lock.unlock();

      ZSTD_inBuffer input = {front.second.data(), front.first, 0};
      while (input.pos < input.size) {
        ZSTD_outBuffer output = {decompressedBuffer.data(),
                                 ZSTD_DStreamOutSize(), 0};

        size_t const ret = ZSTD_decompressStream(dctx, &output, &input);

        if (ZSTD_isError(ret)) {
          ui_print("Error decompressing data: %s", ZSTD_getErrorName(ret));
          close(fd);
          emergency_end.store(true, memory_order_relaxed);
          goto end;
        }

        if (write(fd, decompressedBuffer.data(), output.pos) !=
            static_cast<ssize_t>(output.pos)) {
          ui_print("Error writing data!");
          close(fd);
          emergency_end.store(true, memory_order_relaxed);
          goto end;
        }

        add_progress(output.pos);
      }

      usedRAM -= front.first;
      if (usedRAM.load(memory_order_relaxed) <= MEMORY_LIMIT_PER_THREAD / 2 &&
          !unzip_running.load(memory_order_relaxed)) {
        ram_continue.notify_one();
      }
    }

  end:
    unzstd_finished.store(true, memory_order_relaxed);
    ZSTD_freeDCtx(dctx);
    if (notify_flash && !emergency_end.load(memory_order_relaxed)) {
      ui_print("%s - OK", flash_data.first.c_str());
    }
    ram_continue.notify_one();
  }
};

class Lz4HyperFlash {
private:
  atomic<size_t> usedRAM{0};
  size_t const lz4BufferSize = 128 * 1024;
  queue<pair<size_t, vector<unsigned char>>> buffers;
  mutex mtx;
  atomic<bool> unzip_finished{false};
  atomic<bool> unlz4_finished{false};
  atomic<bool> emergency_end{false};
  atomic<bool> unzip_running{true};
  condition_variable do_lz4;
  condition_variable ram_continue;
  mutex mtx_lz4;
  mutex ram_lock;
  pair<string, string> flash_data;

public:
  Lz4HyperFlash(pair<string, string> d) : flash_data(d) {}

  void unzip() {
    struct archive *a = archive_read_new();
    archive_read_support_format_zip(a);

    if (archive_read_open_filename(a, zip_filename.c_str(), 10240)) {
      ui_print("Failed to open archive: %zu", archive_error_string(a));
      emergency_end.store(true, memory_order_relaxed);
      do_lz4.notify_one();
      archive_read_free(a);
      return;
    }

    vector<unsigned char> compressedBuffer(lz4BufferSize);

    size_t read;
    bool found = false;
    struct archive_entry *entry;
    while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
      const char *filename = archive_entry_pathname(entry);
      if (strcmp(filename, flash_data.first.c_str()) == 0) {
        found = true;
        while ((read = archive_read_data(a, compressedBuffer.data(),
                                         lz4BufferSize)) > 0 &&
               !emergency_end.load(memory_order_relaxed)) {
          {
            lock_guard<mutex> lock(mtx);
            buffers.push(make_pair(read, compressedBuffer));
          }
          do_lz4.notify_one();

          usedRAM += read;
          if (usedRAM.load(memory_order_relaxed) >= MEMORY_LIMIT_PER_THREAD) {
            unzip_running.store(false, memory_order_relaxed);
            unique_lock<mutex> ram(ram_lock);
            ram_continue.wait(ram);
            unzip_running.store(true, memory_order_relaxed);
          }
        }

        break;
      }
    }

    unzip_finished.store(true, memory_order_relaxed);
    archive_read_close(a);
    archive_read_free(a);

    if (!found) {
      ui_print("Could not find %s on archive.", flash_data.first.c_str());
      emergency_end.store(true, memory_order_relaxed);
      do_lz4.notify_one();
    }
  }

  void unlz4() {
    LZ4F_decompressionContext_t dctx;
    LZ4F_createDecompressionContext(&dctx, LZ4F_VERSION);
    if (dctx == nullptr) {
      ui_print("LZ4F_createDecompressionContext() failed!");
      emergency_end.store(true, memory_order_relaxed);
      return;
    }

    int fd =
        open(flash_data.second.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0660);
    if (fd == -1) {
      ui_print("Failed to open %s!", flash_data.second.c_str());
      emergency_end.store(true, memory_order_relaxed);
      LZ4F_freeDecompressionContext(dctx);
      return;
    }

    vector<unsigned char> decompressedBuffer(lz4BufferSize);

    while (!emergency_end.load(memory_order_relaxed)) {
      if (buffers.empty()) {
        if (unzip_finished.load(memory_order_relaxed)) {
          break;
        } else {
          unique_lock<mutex> lz4_lock(mtx_lz4);
          do_lz4.wait(lz4_lock);
          if (emergency_end.load(
                  memory_order_relaxed)) { // Maybe it was notified after a
                                           // failure.
            break;
          }
        }
      }

      unique_lock<mutex> lock(mtx);
      auto front = buffers.front();
      buffers.pop();
      lock.unlock();

      if (front.first == 0)
        break;
      if (front.first < 0) {
        ui_print("LZ4: Error reading input.");
        close(fd);
        emergency_end.store(true, memory_order_relaxed);
        goto end;
      }

      size_t inPos = 0;
      size_t outPos = 0;

      LZ4F_errorCode_t result;
      size_t remaining = front.first;

      while (remaining > 0) {
        size_t dstSize = lz4BufferSize - outPos;
        size_t srcSize = front.first - inPos;
        result =
            LZ4F_decompress(dctx, decompressedBuffer.data() + outPos, &dstSize,
                            front.second.data() + inPos, &srcSize, nullptr);
        if (LZ4F_isError(result)) {
          ui_print("LZ4: %s", LZ4F_getErrorName(result));
          close(fd);
          emergency_end.store(true, memory_order_relaxed);
          goto end;
        }
        inPos += srcSize;
        outPos += dstSize;
        remaining -= srcSize;
        if (write(fd, decompressedBuffer.data(), outPos) !=
            static_cast<ssize_t>(outPos)) {
          ui_print("Error writing data!");
          close(fd);
          emergency_end.store(true, memory_order_relaxed);
          goto end;
        }
        add_progress(outPos);
        outPos = 0;
      }

      usedRAM -= front.first;
      if (usedRAM.load(memory_order_relaxed) <= MEMORY_LIMIT_PER_THREAD / 2 &&
          !unzip_running.load(memory_order_relaxed)) {
        ram_continue.notify_one();
      }
    }

  end:
    unlz4_finished.store(true, memory_order_relaxed);
    LZ4F_freeDecompressionContext(dctx);
    if (notify_flash && !emergency_end.load(memory_order_relaxed)) {
      ui_print("%s - OK", flash_data.first.c_str());
    }
    ram_continue.notify_one();
  }
};

class RawHyperFlash {
private:
  atomic<size_t> usedRAM{0};
  size_t const bufferSize = 128 * 1024;
  queue<pair<size_t, vector<unsigned char>>> buffers;
  mutex mtx;
  atomic<bool> unzip_finished{false};
  atomic<bool> write_finished{false};
  atomic<bool> emergency_end{false};
  atomic<bool> unzip_running{true};
  condition_variable do_write;
  condition_variable ram_continue;
  mutex mtx_write;
  mutex ram_lock;
  pair<string, string> flash_data;

public:
  RawHyperFlash(pair<string, string> d) : flash_data(d) {}

  void unzip() {
    struct archive *a = archive_read_new();
    archive_read_support_format_zip(a);

    if (archive_read_open_filename(a, zip_filename.c_str(), 10240)) {
      ui_print("Failed to open archive: %zu", archive_error_string(a));
      emergency_end.store(true, memory_order_relaxed);
      do_write.notify_one();
      archive_read_free(a);
      return;
    }

    vector<unsigned char> decompressedBuffer(bufferSize);

    size_t read;
    bool found = false;
    struct archive_entry *entry;
    while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
      const char *filename = archive_entry_pathname(entry);
      if (strcmp(filename, flash_data.first.c_str()) == 0) {
        found = true;
        while ((read = archive_read_data(a, decompressedBuffer.data(),
                                         bufferSize)) > 0 &&
               !emergency_end.load(memory_order_relaxed)) {
          {
            lock_guard<mutex> lock(mtx);
            buffers.push(make_pair(read, decompressedBuffer));
          }
          do_write.notify_one();

          usedRAM += read;
          if (usedRAM.load(memory_order_relaxed) >= MEMORY_LIMIT_PER_THREAD) {
            unzip_running.store(false, memory_order_relaxed);
            unique_lock<mutex> ram(ram_lock);
            ram_continue.wait(ram);
            unzip_running.store(true, memory_order_relaxed);
          }
        }

        break;
      }
    }

    unzip_finished.store(true, memory_order_relaxed);
    archive_read_close(a);
    archive_read_free(a);

    if (!found) {
      ui_print("Could not find %s on archive.", flash_data.first.c_str());
    }
  }

  void writer() {
    int fd =
        open(flash_data.second.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0660);
    if (fd == -1) {
      ui_print("Failed to open %s!", flash_data.second.c_str());
      emergency_end.store(true, memory_order_relaxed);
      goto end;
    }

    while (!emergency_end.load(memory_order_relaxed)) {
      if (buffers.empty()) {
        if (unzip_finished.load(memory_order_relaxed)) {
          break;
        } else {
          unique_lock<mutex> write_lock(mtx_write);
          do_write.wait(write_lock);
          if (emergency_end.load(
                  memory_order_relaxed)) { // Maybe it was notified after a
                                           // failure.
            break;
          }
        }
      }
      unique_lock<mutex> lock(mtx);
      auto front = buffers.front();
      buffers.pop();
      lock.unlock();

      if (write(fd, front.second.data(), front.first) !=
          static_cast<ssize_t>(front.first)) {
        ui_print("Error writing data!");
        close(fd);
        emergency_end.store(true, memory_order_relaxed);
        goto end;
      }

      add_progress(front.first);
      usedRAM -= front.first;
      if (usedRAM.load(memory_order_relaxed) <= MEMORY_LIMIT_PER_THREAD / 2 &&
          !unzip_running.load(memory_order_relaxed)) {
        ram_continue.notify_one();
      }
    }
    close(fd);

  end:
    write_finished.store(true, memory_order_relaxed);
    if (notify_flash && !emergency_end.load(memory_order_relaxed)) {
      ui_print("%s - OK", flash_data.first.c_str());
    }
    ram_continue.notify_one();
  }
};

void flashLzmaCompressedFile(pair<string, string> flash_data) {
  LzmaHyperFlash flasher(flash_data);
  thread unzipper(&LzmaHyperFlash::unzip, &flasher);
  thread unlzma(&LzmaHyperFlash::unlzma, &flasher);
  thread writer(&LzmaHyperFlash::writer, &flasher);
  unzipper.join();
  unlzma.join();
  writer.join();
}

void flashBrotliCompressedFile(pair<string, string> flash_data) {
  BrotliHyperFlash flasher(flash_data);
  thread unzipper(&BrotliHyperFlash::unzip, &flasher);
  thread brotlidec(&BrotliHyperFlash::brotlidec, &flasher);
  thread writer(&BrotliHyperFlash::writer, &flasher);
  unzipper.join();
  brotlidec.join();
  writer.join();
}

void flashZstdCompressedFile(pair<string, string> flash_data) {
  ZstdHyperFlash flasher(flash_data);
  thread unzipper(&ZstdHyperFlash::unzip, &flasher);
  thread unzstd(&ZstdHyperFlash::unzstd, &flasher);
  unzipper.join();
  unzstd.join();
}

void flashLz4CompressedFile(pair<string, string> flash_data) {
  Lz4HyperFlash flasher(flash_data);
  thread unzipper(&Lz4HyperFlash::unzip, &flasher);
  thread unlz4(&Lz4HyperFlash::unlz4, &flasher);
  unzipper.join();
  unlz4.join();
}

void flashCompressedFile(pair<string, string> flash_data) {
  if (flash_data.first.ends_with(".lz4"s)) {
    flashLz4CompressedFile(flash_data);
  } else if (flash_data.first.ends_with(".br"s)) {
    flashBrotliCompressedFile(flash_data);
  } else if (flash_data.first.ends_with(".zst"s)) {
    flashZstdCompressedFile(flash_data);
  } else if (flash_data.first.ends_with(".xz"s) ||
             flash_data.first.ends_with(".lzma"s)) {
    flashLzmaCompressedFile(flash_data);
  } else {
    ui_print("Warning: %s has unsupported compression.",
             flash_data.first.c_str());
  }
}

void flashRawFile(pair<string, string> flash_data) {
  RawHyperFlash flasher(flash_data);
  thread unzipper(&RawHyperFlash::unzip, &flasher);
  thread writer(&RawHyperFlash::writer, &flasher);
  unzipper.join();
  writer.join();
}

mapped mapFlashing() {
  mapped allCommands;
  struct archive *a = archive_read_new();
  archive_read_support_format_zip(a);

  if (archive_read_open_filename(a, zip_filename.c_str(), 10240)) {
    ui_print("Failed to open archive: %s", archive_error_string(a));
    archive_read_free(a);
    return allCommands;
  }

  struct archive_entry *entry;
  while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
    const char *filename = archive_entry_pathname(entry);
    if (strcmp(filename, "META-INF/com/google/android/update-commands") == 0) {
      long long nline = 0;
      size_t size = archive_entry_size(entry);
      char buffer[size + 1];
      archive_read_data(a, buffer, size);
      buffer[size] = '\0';

      istringstream iss(buffer);
      string line;

      while (getline(iss, line)) {
        nline += 1;
        if (line.empty() || line[0] == '#') {
          continue;
        }
        vector<string> command;
        if (line.starts_with("ui_print") || line.starts_with("exec_bash") ||
            line.starts_with("exec_check_bash")) {
          command = processSimpleCommand(line);
        } else {
          command = splitByDelimiters(line);
        }
        if (command.size() > 1) {
          allCommands.push_back(command);
        } else {
          ui_print("Invalid command at line %lld", nline);
        }
      }

      break;
    }
  }
  archive_read_close(a);
  archive_read_free(a);
  return allCommands;
}

void check_arguments(const size_t &need, const vector<string> &command) {
  if (command.size() != need) {
    ui_print("Incomplete command: %s, needs %d arguments.", command[0].c_str(),
             need - 1);
    exit(EXIT_FAILURE);
  }
}

string read_prop(const vector<string> &command) {
  check_arguments(3, command);
  string target_prop = command[1];
  string target_value = command[2];
  string prop_value = GetProperty(target_prop);
  if (prop_value.empty()) {
    ui_print("The property %s is empty!", target_prop.c_str());
    return "";
  }
  return prop_value;
}

bool check_prop_startswith(const vector<string> &command) {
  string prop_value = read_prop(command);
  string target_prop = command[1];
  string target_value = command[2];
  if (prop_value.empty()) {
    return false;
  } else if (!prop_value.starts_with(target_value)) {
    ui_print("Check failed! %s does not start with %s.", prop_value.c_str(),
             target_value.c_str());
    return false;
  }
  return true;
}

bool check_prop_endswith(const vector<string> &command) {
  string prop_value = read_prop(command);
  string target_prop = command[1];
  string target_value = command[2];
  if (prop_value.empty()) {
    return false;
  } else if (!prop_value.ends_with(target_value)) {
    ui_print("Check failed! %s does not end with %s.", prop_value.c_str(),
             target_value.c_str());
    return false;
  }
  return true;
}

bool check_prop_equals(const vector<string> &command) {
  string prop_value = read_prop(command);
  string target_prop = command[1];
  string target_value = command[2];
  if (prop_value.empty()) {
    return false;
  } else if (prop_value != target_value) {
    ui_print("Check failed! Expected %s, got %s.", target_value.c_str(),
             prop_value.c_str());
    return false;
  }
  return true;
}

bool check_prop_contains(const vector<string> &command) {
  string prop_value = read_prop(command);
  string target_prop = command[1];
  string target_value = command[2];
  if (prop_value.empty()) {
    return false;
  } else if (prop_value.find(target_value) == string::npos) {
    ui_print("Check failed! Expected %s to contain %s.", prop_value.c_str(),
             target_value.c_str());
    return false;
  }
  return true;
}

void flash_compressed(const vector<string> &command, ThreadManager &manager) {
  check_arguments(3, command);
  pair<string, string> command_args(command[1], command[2]);
  umount_device(command_args.second);
  if (quick_flash) {
    manager.addThread(flashCompressedFile, command_args);
  } else {
    flashCompressedFile(command_args);
  }
}

void flash_raw(const vector<string> &command, ThreadManager &manager) {
  check_arguments(3, command);
  pair<string, string> command_args(command[1], command[2]);
  umount_device(command_args.second);
  if (quick_flash) {
    manager.addThread(flashRawFile, command_args);
  } else {
    flashRawFile(command_args);
  }
}

string removeQuotes(const string &input) {
  string result = input;

  if (result.front() == '\'' || result.front() == '"') {
    result = result.substr(1, result.size() - 2);
  }

  return result;
}

void print_msg(const vector<string> &command) {
  ui_print(removeQuotes(command[1]).c_str());
}

bool parse_boolean(const string &value) {
  return (value == "yes" || value == "YES" || value == "on" || value == "ON" ||
          value == "1" || value == "true" || value == "TRUE");
}

void set_flash_notify(const vector<string> &command) {
  check_arguments(2, command);
  notify_flash = parse_boolean(command[1]);
}

void set_quick_flash(const vector<string> &command) {
  check_arguments(2, command);
  quick_flash = parse_boolean(command[1]);
}

int main(int argc, char *argv[]) {
  if (argc < 4) {
    fprintf(stderr, "Could not find required arguments.\n");
    return 27;
  }

  int tfd;
  try {
    tfd = stoi(argv[2]);
    outfd = fdopen(tfd, "w");

    if (outfd == nullptr) {
      fprintf(stderr, "Error opening fd.\n");
      return 27;
    }
  } catch (...) {
    fprintf(stderr, "Could not get fd\n");
    return 27;
  }

  zip_filename = argv[3];

  mapped allCommands = mapFlashing();
  if (allCommands.empty()) {
    ui_print("Nothing to do (No commands).");
    return EXIT_SUCCESS;
  }

  ThreadManager manager;

  for (const auto &command : allCommands) {
    if (command[0] == "prop_equals") {
      if (!check_prop_equals(command)) {
        return EXIT_FAILURE;
      }
    } else if (command[0] == "prop_contains") {
      if (!check_prop_contains(command)) {
        return EXIT_FAILURE;
      }
    } else if (command[0] == "prop_startswith") {
      if (!check_prop_startswith(command)) {
        return EXIT_FAILURE;
      }
    } else if (command[0] == "prop_endswith") {
      if (!check_prop_endswith(command)) {
        return EXIT_FAILURE;
      }
    } else if (command[0] == "notify_flash") {
      set_flash_notify(command);
    } else if (command[0] == "quick_flash") {
      set_quick_flash(command);
    } else if (command[0] == "ui_print") {
      print_msg(command);
    } else if (command[0] == "set_total_bytes") {
      try {
        totalBytes = static_cast<size_t>(std::stoull(command[1]));
      } catch (...) {
        totalBytes = 0;
        ui_print("!- Out of range totalBytes");
      }
    } else if (command[0] == "exec_bash") {
      system(removeQuotes(command[1]).c_str());
    } else if (command[0] == "exec_check_bash") {
      int i = system(removeQuotes(command[1]).c_str()) >> 8;
      if (i != EXIT_SUCCESS) {
        return i;
      }
    } else if (command[0] == "flash_compressed") {
      flash_compressed(command, manager);
    } else if (command[0] == "flash_raw") {
      flash_raw(command, manager);
    } else {
      ui_print("Unknown command ignored: %s", command[0].c_str());
      continue;
    }
  }

  manager.waitAll();

  return EXIT_SUCCESS;
}
