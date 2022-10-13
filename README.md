# kutil
An x64 linux kernel driver loader and utility.

<div align="center">
    <img src="https://user-images.githubusercontent.com/105472509/170844444-fda8b126-6b23-4bc3-a890-6836ffdcc4b3.png" width="700px"><br>
</div>

## Description
`dpatch` is a PoC kernel driver which patches the system call dispatcher for x64 Linux. It does this by first making a mutable/writeable copy of the 
system call table, overwriting the function pointers in that table with the function pointers of the hook functions, and then patching the first several bytes of the dispatcher to make to jump to a custom system call handler. The custom handler will then index and invoke system calls (or hooks, the function pointer was patched) from the copied (writeable) table.

### Features
- Patches kernel system call dispatcher
- `sys_call_table` isn't touched or modified at all
- Undetected by most, if not all public usermode/kernelmode rootkit scanners

### Bugs
- Decent chance of crashing when the driver gets unloaded (working on fixing this/reducing the chance of crashes) 

### Built with
- C

## Getting started
### Compiling
To compile `dpatch`, simply execute the following script:
- `./build.sh`

### Usage
- `insmod dpatch.ko`

## Credits
```
https://github.com/xmmword
```
### Contributions 🎉
###### All contributions are accepted, simply open an Issue / Pull request.
