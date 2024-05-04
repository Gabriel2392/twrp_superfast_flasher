### For full partitions (.img) only. In development.

This tool is designed for working specifically with full partitions in the .img format. Please note that it's currently in development, so expect updates and improvements over time.

#### Supported Compression Modes:

1. **LZ4**: Extremely Fast. Recommended for achieving the fastest flashing speed. Ideal for those who prioritize speed over compression ratio.

2. **ZSTD**: Very Fast. Recommended for modern machines. It will catch up to your UFS speed and still provide a good compression ratio.

3. **XZ (LZMA2)**: Best Compression Ratio. If you're looking to minimize the size of the zip, this is the recommended. However, it will take longer compared to LZ4 and ZSTD.

4. **RAW**: If you want to store your files in an uncompressed format, you can also do so.
