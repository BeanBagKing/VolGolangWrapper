# vol_wrapper.go
Golang wrapper for Volatility3. Takes in a newline delimited list of plugins (modules) and runs them in parallel.

# Example Usage
```
(vol3) mike@ISAAC:/mnt/c/Users/BBK$ go run vol_wrapper.go -p /home/bbk/volatility3/vol3/bin/vol -i /mnt/c/Users/BBK/mem.dmp -m ./plugins.txt -o /mnt/c/Users/BBK/mem_output/
Using up to 15 goroutines
Running module: windows.crashinfo
Running module: timeliner
Running module: windows.cmdscan
Running module: windows.consoles
Running module: isfinfo
Running module: windows.cachedump
Running module: windows.devicetree
Running module: configwriter
Running module: windows.direct
Running module: windows.callbacks
Running module: windows.debugregisters
Running module: vmscan
Running module: windows.amcache
Running module: windows.bigpools
Running module: windows.cmdline
    Module isfinfo completed in 1.51 seconds
Running module: windows.dlllist
    Module windows.crashinfo completed in 1.98 seconds
    Module configwriter completed in 1.99 seconds
Running module: windows.driverirp
Running module: windows.drivermodule
    Module windows.cmdline completed in 73.31 seconds
[...etc...]
```
# Help
```
$ go run vol_wrapper.go -h
Usage of vol_wrapper.go:
  -i string
        Path to the memory image
  -m string
        Path to file containing list of modules (newline delimited)
  -o string
        Path to the output directory
  -p string
        Path to the Volatility3 executable
```

# Errata
I used the modules keyword instead of plugins by accident at first, but I'm keeping it now. Using plugins would mean a -p flag, so I'd then have to change the Vol Path flag. I can't use -v, that's typically verbose, and I can't use -i because that's already my input file, so maybe something else, or I could just leave it.

the plugins.txt file currently contains the Windows plugins that don't require extra arguments or output raw files. It also excludes Memmap as that's typically unnecessary and takes an order of magnitude longer than any others. The list is sorted in rough order by runtime, with the longest first, in order to reduce the total runtime.
