# Process Memory Scanner

Fast pattern scanning for Linux processes with wildcard support.

## Features

- Read executable regions (`r-xp`) and scan for byte patterns.
- Wildcards (`??`) in patterns for build-to-build stability.
- Efficient chunked scanning to reduce memory usage.
- Example test target with build-dependent bytes.

## Requirements

- Linux
- `gcc` or compatible C compiler
- Permission to read target process memory (`ptrace_scope` may apply)

## Build

```sh
make
```

This produces `process_memory_scanner`.

## Usage

```sh
./process_memory_scanner [-v] [-p pattern_file] <process_name>
```

- `-p`: pattern file path (default: `pattern.txt`)
- `-v`: verbose region scanning logs

Example:
```sh
./process_memory_scanner -v -p pattern.txt mygame
```

### Pattern format

`pattern.txt` example:
```
Pattern: 488d05????????4889c7b800000000
```

- Each pair of hex digits is a byte.
- `??` matches any byte.
- Spaces are allowed.

## Notes

- Scanning other processes may require elevated permissions.
- Use least privilege and only scan authorized processes.

## License

GPL-3.0. See `LICENSE`.
