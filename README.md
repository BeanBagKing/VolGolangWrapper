# vol_wrapper.go
Golang wrapper for Volatility3. Takes in a newline delimited list of plugins (modules) and runs them in parallel.

# Example Usage
```
(vol3) mike@ISAAC:/mnt/c/Users/Mike/Desktop/malware/New$ go run vol_wrapper.go -p /home/mike/volatility3/vol3/bin/vol -i /mnt/c/Users/Mike/Desktop/malware/New/vatsalgupta67/vat_exe.dmp -m ./plugins.txt -o /mnt/c/Users/Mike/Desktop/malware/New/vatsalgupta67/vat_exe/
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
