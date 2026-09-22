# vol_wrapper.go
Golang wrapper for Volatility3. Takes in a newline delimited list of plugins (modules) and runs them in parallel. Outputs all CSV's to a directory.

# Quick Usage
```
git clone https://github.com/BeanBagKing/VolGolangWrapper
cd VolGolangWrapper
./vol_plugin_inventory.py
go run vol_wrapper.go -i <memory.img> -t <linux|windows|mac>
```

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
Run Volatility 3 plugins against a memory image, several at a time,
writing each plugin's output to its own file.

Usage:
  vol_wrapper -i <image> -t <system> [options]
  vol_wrapper -i <image> -m <file>   [options]

Options:
  -d, --debug               Print the full error output of any module that fails
      --force               Overwrite output files from an earlier run
  -i, --image string        Path to the memory image
  -m, --modules string      File listing the modules to run, one per line
      --no-stats            Neither read nor update the runtime statistics
      --no-warmup           Skip warming the symbol cache before running in parallel
  -o, --output string       Directory to write each plugin's output to (default: ./<image>-<UTC timestamp>Z)
      --plugins string      Plugin inventory that -t selects from (default "plugins.csv")
  -r, --renderer string     Volatility output format: csv, json, jsonl, mermaid, pretty, quick (sets the file extension) (default "csv")
      --resume              Keep output files from an earlier run and only run what is missing
      --stats string        Per-plugin runtimes, read for ordering and updated as modules finish (default "plugin_stats.csv")
  -t, --target string       Select modules for this system (windows, linux, mac) instead of -m
  -p, --volatility string   Path to the Volatility 3 executable (default: $VIRTUAL_ENV, then PATH, then ~/volatility3/venv)
  -w, --warmup string       Module used to warm the symbol cache (default: first of windows.info.Info, linux.pslist.PsList, mac.pslist.PsList that runs)

Notes:
  Only -i and one of -t/-m are required. Volatility is found via $VIRTUAL_ENV,
  then PATH, then ~/volatility3/venv; results go to ./<image>-<UTC timestamp>Z
  unless -o says otherwise.
  Modules come from either -t (chosen from plugins.csv) or -m (a list you
  supply), never both. A -t list runs slowest first, using plugin_stats.csv.
  Pressing Enter during a run prints the modules still going.
  Developed under Linux; may or may not work on Windows.

Example:
  vol_wrapper -i 104_Alma_Memory.mem -t linux

```

# Updates
2026-09-21
* Numerous bug fixes, only one major. A downloaded symbols package may start, and during download, other plugs would try to use that incomplete package, resulting in plugin failure. A new "warmup" plugin caches the symbols before starting on parallel processing.
* Numerous new flags added. The old ones still work. See help for all of them. The biggest other than -t to me is -r to pick the renderer (e.g. from csv to jsonl)
* New defaults, these try to autodetect vol path and create default folders
* You can now specify a target type (e.g. windows) and it will run all plugins found for that type, eliminating the need to manually update lists.
* I did not include plugins.csv because then I would have needed to update it with every Volatility release, that's now what vol_plugin_inventory.py is for. Plus it's a much better reference than volatlities help menu.

# Errata
I used the modules keyword instead of plugins by accident at first, but I'm keeping it now. Using plugins would mean a -p flag, so I'd then have to change the Vol Path flag. I can't use -v, that's typically verbose, and I can't use -i because that's already my input file, so maybe something else, or I could just leave it.

the plugins.txt file currently contains the Windows plugins that don't require extra arguments or output raw files. It also excludes Memmap as that's typically unnecessary and takes an order of magnitude longer than any others. The list is sorted in rough order by runtime, with the longest first, in order to reduce the total runtime.
