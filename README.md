
# Process Memory Scanner

Welcome to the Process Memory Scanner project! This tool provides a powerful yet simple C library and executable designed to scan and manipulate the memory of running processes. It is particularly valuable for advanced tasks such as game hacking, where identifying specific values or code within a game's memory is required.

## Features

- **Process Management**: Efficiently create and manage `Process` objects representing running processes.
- **Memory Operations**: Robust methods for reading from and writing to process memory.
- **Pattern Scanning**: Sophisticated scanning of process memory regions for specific byte patterns.
- **Pattern Conversion**: Intelligent conversion of patterns to byte arrays and masks for accurate pattern matching.

## Getting Started

### Prerequisites

Ensure you have the following:
- A C compiler (e.g., `gcc`).
- Sufficient permissions to read the `/proc` filesystem on your Linux system.

### Compilation

To compile the program, execute the following command:

```sh
gcc -o process_memory_scanner main.c Process.c -I.
```

### Running the Program

Execute the program using the following syntax:

```sh
./process_memory_scanner <process_name>
```

For example:

```sh
./process_memory_scanner mygame
```

### Pattern File

Create a `pattern.txt` file containing the pattern you wish to search for, formatted as follows:

```
Pattern: 488d05????????4889c7b800000000
```

In this format, each pair of hexadecimal digits represents a byte, with `??` serving as a wildcard to match any byte.

## How It Works

### Process Management

The library provides an intuitive API to create, manage, and manipulate `Process` objects, allowing you to interact with running processes seamlessly.

#### Key Functions

- `Process* process_create(const char *name);`
  - Initializes a `Process` object by its name and retrieves its PID.
  
- `void process_destroy(Process *proc);`
  - Safely destroys a `Process` object, freeing associated resources.
  
- `pid_t process_get_pid(const Process *proc);`
  - Retrieves the PID of the specified `Process` object.
  
- `void process_set_pid(Process *proc, pid_t pid);`
  - Assigns a PID to the `Process` object.
  
- `const char* process_get_name(const Process *proc);`
  - Obtains the name of the process.
  
- `void process_set_name(Process *proc, const char *name);`
  - Sets the name of the process.

### Memory Operations

- `ssize_t process_read_memory(const Process *proc, unsigned long addr, void *buf, size_t size);`
  - Reads memory from the specified address of the process into a buffer.
  
- `ssize_t process_write_memory(const Process *proc, unsigned long addr, const void *buf, size_t size);`
  - Writes data from a buffer to the specified address of the process memory.

### Pattern Scanning

1. **Pattern Conversion**: Converts the pattern specified in the `pattern.txt` file into a byte array and mask array, handling wildcards (`??`) effectively.
2. **Memory Region Listing**: Parses memory regions from `/proc/[pid]/maps`, filtering for regions with read and execute permissions (`r-xp`).
3. **Memory Scanning**: Scans each `r-xp` region for the specified pattern, printing the address of any matches found.

#### Example Output

```
Process name: mygame, PID: 12345
Debug: Found r-xp region from 0x400000 to 0x401000
Debug: Reading memory from 0x400000 to 0x401000
Debug: Pattern matched at offset 128 in region 0x400000 to 0x401000
Pattern found at address: 0x400080
```

## Usage Notes

This tool is intended for educational purposes and should be used responsibly. Unauthorized scanning and modification of process memory can lead to unintended consequences and may violate the terms of service of some software applications.

## License

This project is licensed under the MIT License.

---

We trust that this tool will enhance your understanding and capabilities in process memory management. Use it ethically and responsibly, and happy hacking!

---
