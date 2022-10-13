# dpatch
An x64 PoC kernel driver that hooks system calls via patching the Linux system call dispatcher.

<div align="center">
    <img src="https://user-images.githubusercontent.com/105472509/195727127-49de8c41-5af5-4b9a-af33-028735e21c98.PNG" width="700px"><br>
</div>

## Description
`dpatch` is a PoC kernel driver which patches the system call dispatcher for x64 Linux. It does this by first making a mutable/writeable copy of the 
system call table, overwriting the function pointers in that table with the function pointers that point to the hook functions, and then patching the first several bytes of the dispatcher to make it jump to a custom system call handler. The custom handler will then index and invoke system calls (or hooks, if the function pointer was overwritten) from the copied (writeable) table.

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
