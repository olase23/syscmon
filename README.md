# syscmon
syscmon is a linux kernel subsystem that monitors the system call integrity. It checks periodical the sys_call_table and system call target addresses on the CPU(s).
Changes on the syscall structures are logged on the /proc file system.

```
cat /proc/syscall_monitor 
changed syscall number  origin address         new address                    module name
60                      ffffffff81068240       ffffffffa0000000               interceptor

```

