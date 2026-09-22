// Command vol_wrapper runs a list of Volatility 3 plugins against a single
// memory image, several at a time, and writes each plugin's CSV output to its
// own file in an output directory.
//
// The plugin list is a newline-delimited text file. Concurrency is capped at
// one less than the number of logical CPUs. Pressing Enter during a run prints
// the plugins still in flight.
//
// Usage:
//
//	go run vol_wrapper.go -p <vol> -i <image> -m <plugins.txt> -o <outdir>
package main

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	flag "github.com/spf13/pflag"
)

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

// config holds the four required command-line paths.
type config struct {
	volatilityPath string              // the Volatility 3 executable to invoke
	memoryImage    string              // the image every plugin is run against
	modulesFile    string              // newline-delimited list of plugins to run
	outputDir      string              // directory the per-plugin CSVs are written to
	debug          bool                // print a failing plugin's full error output
	warmupModule   string              // plugin used to prime the symbol cache ("" = auto)
	skipWarmup     bool                // run the batch without priming the symbol cache
	statsFile      string              // per-plugin runtimes, read and updated
	skipStats      bool                // run without reading or updating them
	renderer       string              // Volatility output format, and the file extension
	force          bool                // overwrite results from an earlier run
	resume         bool                // keep them, and run only what is missing
	target         string              // operating system to select plugins for
	pluginsFile    string              // the inventory those plugins are chosen from
	extraArgs      map[string][]string // per-module arguments supplied at the prompt
}

// parseFlags reads the command line and fails if the arguments do not make a
// runnable request.
func parseFlags() config {
	var cfg config
	flag.StringVarP(&cfg.volatilityPath, "volatility", "p", "",
		"Path to the Volatility 3 executable (default: $VIRTUAL_ENV, then PATH, then ~/volatility3/venv)")
	flag.StringVarP(&cfg.memoryImage, "image", "i", "", "Path to the memory image")
	flag.StringVarP(&cfg.outputDir, "output", "o", "",
		"Directory to write each plugin's output to (default: ./<image>-<UTC timestamp>Z)")
	flag.StringVarP(&cfg.modulesFile, "modules", "m", "", "File listing the modules to run, one per line")
	flag.StringVarP(&cfg.renderer, "renderer", "r", "csv",
		"Volatility output format: "+strings.Join(rendererNames(), ", ")+" (sets the file extension)")
	flag.StringVarP(&cfg.target, "target", "t", "", "Select modules for this system (windows, linux, mac) instead of -m")
	flag.StringVarP(&cfg.warmupModule, "warmup", "w", "", "Module used to warm the symbol cache (default: first of "+strings.Join(warmupCandidates, ", ")+" that runs)")
	flag.BoolVarP(&cfg.debug, "debug", "d", false, "Print the full error output of any module that fails")
	flag.StringVar(&cfg.pluginsFile, "plugins", defaultPluginsFile, "Plugin inventory that -t selects from")
	flag.StringVar(&cfg.statsFile, "stats", defaultStatsFile, "Per-plugin runtimes, read for ordering and updated as modules finish")
	flag.BoolVar(&cfg.force, "force", false, "Overwrite output files from an earlier run")
	flag.BoolVar(&cfg.resume, "resume", false, "Keep output files from an earlier run and only run what is missing")
	flag.BoolVar(&cfg.skipWarmup, "no-warmup", false, "Skip warming the symbol cache before running in parallel")
	flag.BoolVar(&cfg.skipStats, "no-stats", false, "Neither read nor update the runtime statistics")
	flag.Usage = printUsage
	flag.Parse()

	if cfg.volatilityPath == "" {
		cfg.volatilityPath = defaultVolatility()
		if cfg.volatilityPath == "" {
			fmt.Fprintln(os.Stderr, "Could not find a Volatility 3 executable.")
			fmt.Fprintln(os.Stderr, "Looked at $VIRTUAL_ENV, then PATH, then ~/volatility3/venv.")
			fmt.Fprintln(os.Stderr, "Give one with -p/--volatility.")
			os.Exit(1)
		}
		// Said out loud: which Volatility produced a result is part of the
		// result, and a default nobody sees is a default nobody checks.
		fmt.Printf("Using Volatility at %s\n", cfg.volatilityPath)
	}

	var missing []string
	if cfg.memoryImage == "" {
		missing = append(missing, "-i/--image")
	}
	if len(missing) > 0 {
		fmt.Fprintf(os.Stderr, "Missing required flag(s): %s\n", strings.Join(missing, ", "))
		fmt.Fprintf(os.Stderr, "Run %s --help for usage.\n", programName())
		os.Exit(1)
	}
	// After -i is known to be present, since the name is built from it.
	if cfg.outputDir == "" {
		cfg.outputDir = defaultOutputDir(cfg.memoryImage)
		// Announced because the caller needs it: to find the results, and to
		// pass back with -o for --resume.
		fmt.Printf("Writing results to %s\n", cfg.outputDir)
	}

	if _, ok := rendererExtensions[cfg.renderer]; !ok {
		fmt.Fprintf(os.Stderr, "Unknown renderer %q; choose one of: %s\n",
			cfg.renderer, strings.Join(rendererNames(), ", "))
		os.Exit(1)
	}

	if cfg.force && cfg.resume {
		fmt.Fprintln(os.Stderr, "--force and --resume ask for opposite things; give at most one.")
		os.Exit(1)
	}
	// Exactly one source of modules: an explicit list, or a target to derive
	// one from.
	if (cfg.modulesFile == "") == (cfg.target == "") {
		fmt.Fprintln(os.Stderr, "Give exactly one of -m/--modules (a list file) or -t/--target (a system).")
		fmt.Fprintf(os.Stderr, "Run %s --help for usage.\n", programName())
		os.Exit(1)
	}
	return cfg
}

// programName is how the tool was invoked, for use in help text.
func programName() string {
	return filepath.Base(os.Args[0])
}

// printUsage replaces pflag's default usage output.
func printUsage() {
	name := programName()
	fmt.Fprintf(os.Stderr, `Run Volatility 3 plugins against a memory image, several at a time,
writing each plugin's output to its own file.

Usage:
  %s -i <image> -t <system> [options]
  %s -i <image> -m <file>   [options]

Options:
%s
Notes:
  Only -i and one of -t/-m are required. Volatility is found via $VIRTUAL_ENV,
  then PATH, then ~/volatility3/venv; results go to ./<image>-<UTC timestamp>Z
  unless -o says otherwise.
  Modules come from either -t (chosen from %s) or -m (a list you
  supply), never both. A -t list runs slowest first, using %s.
  Pressing Enter during a run prints the modules still going.
  Developed under Linux; may or may not work on Windows.

Example:
  %s -i 104_Alma_Memory.mem -t linux
`, name, name, flag.CommandLine.FlagUsages(), defaultPluginsFile, defaultStatsFile, name)
}

// ---------------------------------------------------------------------------
// Finding Volatility
// ---------------------------------------------------------------------------

// venvBinary names an executable inside a virtualenv, which keeps its programs
// in bin/ everywhere except Windows.
func venvBinary(root, name string) string {
	if runtime.GOOS == "windows" {
		return filepath.Join(root, "Scripts", name+".exe")
	}
	return filepath.Join(root, "bin", name)
}

func isExecutableFile(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	return runtime.GOOS == "windows" || info.Mode()&0o111 != 0
}

// defaultOutputDir names a directory in the working directory to hold one
// run's results: <image name>-<UTC timestamp>.
//
// The image name comes first so repeated runs against the same evidence sort
// together, and the extension is dropped because ".mem" reads badly in front
// of a timestamp. The timestamp is UTC, and says so: a bare local time is
// ambiguous across timezones and DST, which evidence timestamps should not be.
//
// The image name is also in every filename inside, but a directory travels on
// its own -- zipped, moved, mailed -- and "20260921_223015" alone says nothing
// about what it holds.
func defaultOutputDir(memoryImage string) string {
	name := filepath.Base(memoryImage)
	name = strings.TrimSuffix(name, filepath.Ext(name))
	return fmt.Sprintf("%s-%sZ", name, time.Now().UTC().Format("20060102_150405"))
}

// defaultVolatility locates the vol executable when -p is not given.
//
// An activated virtualenv is checked first, by its own name, so a venv called
// anything other than "venv" still works. PATH comes next, covering a system
// or pipx install. The documented layout is the last resort.
func defaultVolatility() string {
	if venv := os.Getenv("VIRTUAL_ENV"); venv != "" {
		if path := venvBinary(venv, "vol"); isExecutableFile(path) {
			return path
		}
	}
	if path, err := exec.LookPath("vol"); err == nil {
		return path
	}
	if home, err := os.UserHomeDir(); err == nil {
		if path := venvBinary(filepath.Join(home, "volatility3", "venv"), "vol"); isExecutableFile(path) {
			return path
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// Module list
// ---------------------------------------------------------------------------

// readModules loads the plugin names to run, one per line, skipping blanks.
//
// Lines are trimmed before the blank test: a line of spaces is blank to a
// reader, and passing "   " to Volatility as a plugin name just produces a
// confusing failure.
func readModules(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	modules := []string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if module := strings.TrimSpace(scanner.Text()); module != "" {
			modules = append(modules, module)
		}
	}
	return modules, scanner.Err()
}

// ---------------------------------------------------------------------------
// Progress reporting
// ---------------------------------------------------------------------------

// runningModules maps the name of each in-flight plugin to the time it began.
var runningModules sync.Map

// monitorKeyPress prints the plugins still running each time a key is pressed,
// and returns once stdin can no longer be read.
//
// Returning on error is the whole point: at EOF -- which is what stdin is under
// nohup, cron, a pipe or a CI runner -- ReadByte fails immediately, so retrying
// spins at 100% of one core for the life of the run. That is precisely the core
// the NumCPU-1 worker cap sets out to leave free. Key press reporting is
// meaningless without a terminal, so stopping loses nothing.
func monitorKeyPress(debug bool) {
	reader := bufio.NewReader(os.Stdin)
	for {
		if _, err := reader.ReadByte(); err != nil { // Wait for a key press
			if debug {
				fmt.Printf("!    [monitor] stopped watching stdin: %v\n", err)
			}
			return
		}

		fmt.Println("\n->->->->->->->->->-> Currently running modules <-<-<-<-<-<-<-<-<-<-")
		runningModules.Range(func(key, value interface{}) bool {
			module := key.(string)
			start := value.(time.Time)
			runtime := time.Since(start).Seconds()
			fmt.Printf("Module: %s, Runtime: %.2f seconds\n", module, runtime)
			return true
		})
		// Print rather than Println: the banner is followed by a blank line,
		// and Println with a trailing newline is what go vet objects to. Both
		// newlines are kept, so the output is unchanged.
		fmt.Print("->->->->->->->->->->->->->->-> End <-<-<-<-<-<-<-<-<-<-<-<-<-<-<-\n\n")
	}
}

// ---------------------------------------------------------------------------
// Capturing why a module failed
// ---------------------------------------------------------------------------

const (
	// How much of a failing plugin's stderr to keep. Volatility streams progress
	// on stderr, so the whole stream is unbounded and mostly noise; a traceback
	// appears at the end, which is the part worth keeping.
	maxStderrBytes = 64 << 10
	// How many of those trailing lines to print.
	maxStderrLines = 20
)

// stderrTail is an io.Writer keeping only the last maxStderrBytes written.
// exec.Cmd drives it from a single goroutine per command, so it needs no lock.
type stderrTail struct {
	buf []byte
}

func (t *stderrTail) Write(p []byte) (int, error) {
	t.buf = append(t.buf, p...)
	if len(t.buf) > maxStderrBytes {
		t.buf = t.buf[len(t.buf)-maxStderrBytes:]
	}
	return len(p), nil
}

// lines returns the last n non-blank lines held. Volatility's progress output
// separates updates with carriage returns, so those break lines here too.
func (t *stderrTail) lines(n int) []string {
	split := strings.FieldsFunc(string(t.buf), func(r rune) bool {
		return r == '\n' || r == '\r'
	})
	kept := make([]string, 0, len(split))
	for _, line := range split {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			kept = append(kept, trimmed)
		}
	}
	if len(kept) > n {
		kept = kept[len(kept)-n:]
	}
	return kept
}

// summary returns the last non-blank line held, which for a Python traceback
// is the exception itself -- enough to say why a module failed on one line.
func (t *stderrTail) summary() string {
	if lines := t.lines(1); len(lines) > 0 {
		return lines[0]
	}
	return ""
}

// ---------------------------------------------------------------------------
// Running one module
// ---------------------------------------------------------------------------

// Suffix of the file a plugin's output is written to while it runs. A CSV
// only takes its real name once the plugin has exited successfully, so the
// output directory never contains a file that is empty, truncated, or still
// being written. A leftover .partial marks a run that was killed.
const partialSuffix = ".partial"

// Volatility's renderers, mapped to the file extension each one deserves.
//
// "none" is deliberately absent: it produces no output at all, and this tool
// exists to collect output. Offering it would write a directory of empty files.
var rendererExtensions = map[string]string{
	"csv":     "csv",
	"json":    "json",
	"jsonl":   "jsonl",
	"pretty":  "txt",
	"quick":   "txt",
	"mermaid": "mmd",
}

func rendererNames() []string {
	names := make([]string, 0, len(rendererExtensions))
	for name := range rendererExtensions {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// outputPath names the file for one plugin:
// <outputDir>/<image>_<module>.<extension for the chosen renderer>.
//
// The extension follows the format, so a json run and a csv run in the same
// directory are different files -- which also means they do not trip the
// overwrite check against each other.
//
// filepath rather than string surgery: filepath.Base understands both
// separators on Windows, and filepath.Join cleans the result, so a -o given
// with a trailing slash no longer yields a doubled one.
func outputPath(cfg config, module string) string {
	return filepath.Join(cfg.outputDir, fmt.Sprintf("%s_%s.%s",
		filepath.Base(cfg.memoryImage), module, rendererExtensions[cfg.renderer]))
}

// runModule runs one plugin to completion, writing its CSV to outputDir.
// Volatility's stderr is captured rather than discarded, so that when a plugin
// fails the reason can be reported instead of only its exit status. The full
// capture is printed only under --debug; otherwise just its last line.
// runModule reports whether the module produced usable output, so the process
// can exit non-zero when some of the work did not happen.
func runModule(cfg config, module string, stats *statsTable) (ok bool) {
	start := time.Now()
	runningModules.Store(module, start)
	defer runningModules.Delete(module)

	finalPath := outputPath(cfg, module)
	partialPath := finalPath + partialSuffix

	// Anything the user supplied at the prompt goes after the plugin name,
	// where Volatility expects a plugin's own options.
	args := append([]string{"-f", cfg.memoryImage, "-r", cfg.renderer, module},
		cfg.extraArgs[module]...)
	cmd := exec.Command(cfg.volatilityPath, args...)
	outfile, err := os.Create(partialPath)
	if err != nil {
		fmt.Printf("Error creating output file for module %s: %v\n", module, err)
		return false
	}

	var stderr stderrTail
	cmd.Stdout = outfile
	cmd.Stderr = &stderr // Captured, and only shown if the module fails

	fmt.Printf("Running module: %s\n", module)
	runErr := cmd.Run()
	// Closed explicitly rather than deferred: the rename below must not race
	// the last buffered write.
	closeErr := outfile.Close()

	if runErr != nil {
		// Nothing usable was produced, so leave no file behind; an empty or
		// half-written CSV is worse than none.
		os.Remove(partialPath)
		// One line by default: the exit status plus the exception that caused
		// it, which is almost always the useful part.
		if summary := stderr.summary(); summary != "" {
			fmt.Printf("!--- Error running module %s: %v - %q\n", module, runErr, summary)
		} else {
			fmt.Printf("!--- Error running module %s: %v\n", module, runErr)
		}
		if cfg.debug {
			// Every line carries the module name: modules run concurrently, so
			// unprefixed multi-line output could not be attributed to one.
			for _, line := range stderr.lines(maxStderrLines) {
				fmt.Printf("!    [%s] %s\n", module, line)
			}
		}
		return false
	}

	if closeErr != nil {
		os.Remove(partialPath)
		fmt.Printf("!--- Error writing output for module %s: %v\n", module, closeErr)
		return false
	}
	if err := os.Rename(partialPath, finalPath); err != nil {
		os.Remove(partialPath)
		fmt.Printf("!--- Error writing output for module %s: %v\n", module, err)
		return false
	}

	duration := time.Since(start).Seconds()
	// Only successful runs are recorded; see pluginStat.record. Written out
	// immediately so an interrupted batch keeps what it measured.
	if stats != nil {
		stats.recordRun(module, duration)
	}
	fmt.Printf("    Module %s completed in %.2f seconds\n", module, duration)
	return true
}

// ---------------------------------------------------------------------------
// Selecting modules for a target system
// ---------------------------------------------------------------------------

const defaultPluginsFile = "plugins.csv"

// A plugin is run against a target system when it is written for that system
// or for any system, it needs no arguments we cannot supply, and it has not
// been superseded.
//
// TargetSystem "NA" is deliberately not selected: frameworkinfo and isfinfo
// report on Volatility itself and never read the image.
//
// BulkSupport already excludes both plugins that require a flag and plugins
// that write files unasked -- dumpfiles, layerwriter, configwriter,
// pagecache.RecoverFs -- so no separate exclusion list is needed.
//
// Deprecated is excluded because every deprecated plugin's replacement is
// itself selected by these same rules, so nothing is lost by skipping the
// shim.
type pluginRow struct {
	fullName        string
	targetSystem    string
	bulkSupport     bool
	deprecated      bool
	additionalFlags string
}

// flagsByModule maps each plugin to the options it advertises, for deciding
// which ones have to be asked about.
func flagsByModule(rows []pluginRow) map[string]string {
	flags := make(map[string]string, len(rows))
	for _, row := range rows {
		flags[row.fullName] = row.additionalFlags
	}
	return flags
}

func loadPlugins(path string) ([]pluginRow, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	reader.FieldsPerRecord = -1
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("%s is empty", path)
	}

	index := map[string]int{}
	for i, name := range records[0] {
		index[name] = i
	}
	for _, needed := range []string{"FullName", "TargetSystem", "BulkSupport", "Deprecated"} {
		if _, ok := index[needed]; !ok {
			return nil, fmt.Errorf("%s has no %s column", path, needed)
		}
	}
	field := func(row []string, name string) string {
		if i := index[name]; i < len(row) {
			return strings.TrimSpace(row[i])
		}
		return ""
	}

	var rows []pluginRow
	for _, record := range records[1:] {
		if name := field(record, "FullName"); name != "" {
			rows = append(rows, pluginRow{
				fullName:     name,
				targetSystem: field(record, "TargetSystem"),
				bulkSupport:  strings.EqualFold(field(record, "BulkSupport"), "true"),
				deprecated:   strings.EqualFold(field(record, "Deprecated"), "true"),
				// Optional: only -t needs it, and only for the argument prompt.
				additionalFlags: field(record, "AdditionalFlags"),
			})
		}
	}
	return rows, nil
}

// knownTargets lists the system names the inventory actually contains, so the
// error message stays correct if Volatility grows support for another one.
func knownTargets(rows []pluginRow) []string {
	seen := map[string]bool{}
	var targets []string
	for _, row := range rows {
		if row.targetSystem == "" || row.targetSystem == "All" || row.targetSystem == "NA" {
			continue
		}
		if !seen[row.targetSystem] {
			seen[row.targetSystem] = true
			targets = append(targets, row.targetSystem)
		}
	}
	sort.Strings(targets)
	return targets
}

// selectModules picks every plugin worth running against the target system.
func selectModules(rows []pluginRow, target string) ([]string, error) {
	// Validate the target first. Plugins marked "All" match whatever is asked
	// for, so without this a misspelled target would quietly select just those
	// few and look like a successful, very short run.
	targets := knownTargets(rows)
	recognised := false
	for _, known := range targets {
		if strings.EqualFold(known, target) {
			recognised = true
			break
		}
	}
	if !recognised {
		return nil, fmt.Errorf("unknown target %q; %s has plugins for: %s",
			target, defaultPluginsFile, strings.Join(targets, ", "))
	}

	var modules []string
	for _, row := range rows {
		if !row.bulkSupport || row.deprecated {
			continue
		}
		if strings.EqualFold(row.targetSystem, target) || row.targetSystem == "All" {
			modules = append(modules, row.fullName)
		}
	}
	if len(modules) == 0 {
		return nil, fmt.Errorf("no runnable modules for target %q", target)
	}
	return modules, nil
}

// orderByRuntime sorts longest-running first, so the slowest plugins start
// while there are still free workers and the run finishes sooner. Ties break
// on name to keep the order reproducible.
func orderByRuntime(modules []string, stats *statsTable) {
	sort.SliceStable(modules, func(i, j int) bool {
		if stats == nil {
			return modules[i] < modules[j]
		}
		a, b := stats.weight(modules[i]), stats.weight(modules[j])
		if a != b {
			return a > b
		}
		return modules[i] < modules[j]
	})
}

// ---------------------------------------------------------------------------
// Asking for arguments a plugin cannot run without
// ---------------------------------------------------------------------------

// Some plugins declare no *required* flag, so they pass the BulkSupport test,
// yet fail immediately without one: the yara scanners need a rule from
// somewhere and exit with "No rules provided to YaraScanner" otherwise.
//
// Matching on the flags alone is not enough, and this was got wrong once. The
// full yara option group is also exposed by plugins that ship their own rules
// and offer the flags only as an override -- windows.malware.
// direct_system_calls and indirect_system_calls among them. Measured against
// the Alma and Windows images: the flag group alone matches 7 plugins, 4 of
// which run perfectly well with no arguments (rc=0, one of them 422 rows),
// while the 3 whose name contains "yarascan" are exactly the 3 that fail.
//
// So both must hold: the flags prove it accepts a rule, the name proves it has
// none of its own.
var argumentPrompts = []struct {
	description string
	namePart    string
	flags       []string
}{
	{"yara rules", "yarascan", []string{"--yara-string", "--yara-file", "--yara-compiled-file"}},
}

// promptNeeded reports what a plugin must be given, judging by its name and
// the flags it offers.
func promptNeeded(module, additionalFlags string) (string, bool) {
	lower := strings.ToLower(module)
	for _, prompt := range argumentPrompts {
		if !strings.Contains(lower, prompt.namePart) {
			continue
		}
		complete := true
		for _, flag := range prompt.flags {
			if !strings.Contains(additionalFlags, flag) {
				complete = false
				break
			}
		}
		if complete {
			return prompt.description, true
		}
	}
	return "", false
}

// stdinIsTerminal reports whether stdin *might* have a person behind it.
//
// This is deliberately a cheap test rather than a real isatty ioctl, which
// would mean a dependency. It answers false for a pipe or a file, and true for
// any character device -- which includes /dev/null, the usual stdin under
// nohup and cron. That case is caught instead by the first read returning EOF
// immediately, so nothing ever blocks; see readAnswer.
func stdinIsTerminal() bool {
	info, err := os.Stdin.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

// readAnswer reads one reply. closed reports that stdin is at EOF, meaning
// nobody is there and no further prompt should be printed.
func readAnswer(reader *bufio.Reader) (answer string, closed bool) {
	line, err := reader.ReadString('\n')
	if err != nil && strings.TrimSpace(line) == "" {
		return "", true
	}
	return strings.TrimSpace(line), false
}

// splitArgs splits a typed command line the way a shell would: on whitespace,
// honouring single and double quotes, with a backslash escaping the next
// character except inside single quotes.
//
// The escape handling is not optional. A yara rule is written
//
//	--yara-string "rule x { strings: $a = \"abc def\" condition: $a }"
//
// and without it the inner \" closes the quote, so the rule arrives as two
// mangled arguments instead of one.
func splitArgs(line string) []string {
	var args []string
	var current strings.Builder
	var quote rune
	inWord, escaped := false, false

	for _, r := range line {
		switch {
		case escaped:
			current.WriteRune(r)
			inWord, escaped = true, false
		case r == '\\' && quote != '\'':
			escaped, inWord = true, true
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				current.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote = r
			inWord = true
		case r == ' ' || r == '\t':
			if inWord {
				args = append(args, current.String())
				current.Reset()
				inWord = false
			}
		default:
			current.WriteRune(r)
			inWord = true
		}
	}
	if inWord {
		args = append(args, current.String())
	}
	return args
}

// resolveArguments asks about any selected plugin that needs arguments, and
// drops the ones left unanswered.
//
// It must run before the key press monitor starts: both read stdin, and they
// would steal bytes from one another.
func resolveArguments(modules []string, flagsByModule map[string]string) ([]string, map[string][]string) {
	extra := map[string][]string{}
	var needing []string
	for _, module := range modules {
		if _, ok := promptNeeded(module, flagsByModule[module]); ok {
			needing = append(needing, module)
		}
	}
	if len(needing) == 0 {
		return modules, extra
	}

	if !stdinIsTerminal() {
		fmt.Printf("!--- %d module(s) need arguments and stdin is not a terminal; skipping them:\n",
			len(needing))
		for _, module := range needing {
			fmt.Printf("!    %s\n", module)
		}
		return without(modules, needing), extra
	}

	reader := bufio.NewReader(os.Stdin)
	var skipped []string
	for index, module := range needing {
		description, _ := promptNeeded(module, flagsByModule[module])
		fmt.Printf("%s needs %s. Enter additional arguments, or press Enter to skip: ",
			module, description)
		answer, closed := readAnswer(reader)
		if closed {
			// Nobody is there after all: stop prompting rather than printing
			// questions into a void, and skip everything still outstanding.
			fmt.Printf("\n!--- stdin is not interactive; skipping %d module(s) needing arguments.\n",
				len(needing)-index)
			skipped = append(skipped, needing[index:]...)
			break
		}
		if args := splitArgs(answer); len(args) > 0 {
			extra[module] = args
		} else {
			skipped = append(skipped, module)
		}
	}
	for _, module := range skipped {
		fmt.Printf("    Skipping %s\n", module)
	}
	return without(modules, skipped), extra
}

// without returns modules with every name in remove taken out, order intact.
func without(modules, remove []string) []string {
	if len(remove) == 0 {
		return modules
	}
	dropped := make(map[string]bool, len(remove))
	for _, name := range remove {
		dropped[name] = true
	}
	kept := modules[:0:0]
	for _, module := range modules {
		if !dropped[module] {
			kept = append(kept, module)
		}
	}
	return kept
}

// ---------------------------------------------------------------------------
// Runtime statistics
// ---------------------------------------------------------------------------

// How long a plugin takes cannot be read from Volatility's source or API, so
// it is measured and kept here rather than in plugins.csv, which is a
// generated file and would lose the column on its next rebuild.
const (
	defaultStatsFile = "plugin_stats.csv"
	// Ordering weight for a plugin never yet timed. An unmeasured plugin
	// sorts first, which is the safe assumption for a longest-first run.
	unknownRuntime = 9999.0
)

var statsFields = []string{"FullName", "Default", "LastRun", "BestRun", "WorstRun", "AvgRun", "AllRuns"}

// pluginStat is one plugin's ordering weight and measured history.
//
// runs is the only state: last, best, worst and average are all functions of
// it, recomputed on demand rather than tracked alongside. Editing AllRuns in
// the file therefore corrects every derived column on the next write, and no
// derived value can drift from the samples it claims to describe.
//
// def is the seeded Default, measured on other hardware against other images.
// It is read and never written, and it is consulted only while runs is empty
// -- so from a plugin's very first local run onward, nothing about the
// ordering depends on foreign hardware.
type pluginStat struct {
	def  float64
	runs []float64
}

// measured reports whether this machine has timed the plugin. Until it has,
// the run-history columns are blank and ordering falls back to def.
func (p *pluginStat) measured() bool { return len(p.runs) > 0 }

func (p *pluginStat) last() float64 { return p.runs[len(p.runs)-1] }

func (p *pluginStat) best() float64 {
	best := p.runs[0]
	for _, value := range p.runs[1:] {
		if value < best {
			best = value
		}
	}
	return best
}

func (p *pluginStat) worst() float64 {
	worst := p.runs[0]
	for _, value := range p.runs[1:] {
		if value > worst {
			worst = value
		}
	}
	return worst
}

// average folds the samples oldest to newest, each step taking the midpoint of
// the running value and the next sample. The newest run therefore carries half
// the weight, the one before it a quarter, and so on. This is not the
// arithmetic mean -- AllRuns keeps every sample so the mean, the median or
// anything else can be computed instead without re-measuring.
func (p *pluginStat) average() float64 {
	average := p.runs[0]
	for _, value := range p.runs[1:] {
		average = (average + value) / 2
	}
	return average
}

// weight is the ordering key: this machine's own average once there is one,
// otherwise the seeded default.
func (p *pluginStat) weight() float64 {
	if p.measured() {
		return p.average()
	}
	if p.def > 0 {
		return p.def
	}
	return unknownRuntime
}

// record adds one successful run. Failed runs are not recorded: a plugin that
// dies in 0.2s would otherwise set a BestRun it can never legitimately
// achieve, and sort last forever after.
func (p *pluginStat) record(seconds float64) {
	// Rounded on the way in, so every derived column is a whole number too
	// and the stored samples are exactly what the file shows.
	p.runs = append(p.runs, math.Round(seconds))
}

// statsTable is the whole file, kept in its original row order so rewriting it
// produces a minimal diff. Modules finish concurrently, hence the mutex.
type statsTable struct {
	mu      sync.Mutex
	order   []string
	rows    map[string]*pluginStat
	path    string // where it persists, so a run can be saved as it goes
	warned  bool   // a save failure has been reported; do not repeat it
	existed bool   // the file was there at startup, so seeded Defaults are known
}

func newStatsTable() *statsTable {
	return &statsTable{rows: map[string]*pluginStat{}}
}

// seedMissing gives every name it does not already know a row carrying the
// unknown default, and returns how many it added.
//
// Called before anything runs, so a plugin new to the inventory appears in the
// file whether or not it succeeds -- or even gets as far as running. Adding it
// only on success would hide a plugin that always fails, which is exactly the
// one worth noticing, and would lose the row entirely if the batch were
// interrupted first.
func (t *statsTable) seedMissing(names []string) int {
	added := 0
	t.mu.Lock()
	for _, name := range names {
		if _, exists := t.rows[name]; !exists {
			t.rows[name] = &pluginStat{def: unknownRuntime}
			t.order = append(t.order, name)
			added++
		}
	}
	t.mu.Unlock()

	if added > 0 && t.path != "" {
		if err := t.save(t.path); err != nil {
			fmt.Printf("!--- Warning: could not write %s: %v\n", t.path, err)
		}
	}
	return added
}

// pluginNames lists the inventory's plugins in its own order.
func pluginNames(rows []pluginRow) []string {
	names := make([]string, 0, len(rows))
	for _, row := range rows {
		names = append(names, row.fullName)
	}
	return names
}

// recordRun adds one successful run and writes the file immediately.
//
// Saving per module rather than once at the end means a run that is killed
// part-way keeps every measurement it had already made. A full rewrite of a
// couple of hundred rows costs far less than the plugin that just finished,
// and save() serialises on the same mutex, so concurrent finishers cannot
// interleave writes or collide on the temporary file.
func (t *statsTable) recordRun(module string, seconds float64) {
	t.record(module, seconds)
	if t.path == "" {
		return
	}
	if err := t.save(t.path); err != nil {
		t.mu.Lock()
		first := !t.warned
		t.warned = true
		t.mu.Unlock()
		// Reported once: a failing path would otherwise warn on every module.
		if first {
			fmt.Printf("!--- Warning: could not write %s: %v\n", t.path, err)
			fmt.Printf("!--- Runtime statistics for this run will not be kept.\n")
		}
	}
}

func parseRuns(field string) []float64 {
	field = strings.TrimSpace(strings.Trim(strings.TrimSpace(field), "[]"))
	if field == "" {
		return nil
	}
	var runs []float64
	for _, part := range strings.Split(field, ",") {
		if value, err := strconv.ParseFloat(strings.TrimSpace(part), 64); err == nil {
			// Rounded on read as well, so a file written before this or edited
			// by hand is normalised rather than carried forward with decimals.
			runs = append(runs, math.Round(value))
		}
	}
	return runs
}

// formatRuns renders samples as one cell: [55.33,64.7,72.52]. An empty history
// is written blank, not "[]", so an untouched row stays exactly as seeded.
func formatRuns(runs []float64) string {
	if len(runs) == 0 {
		return ""
	}
	parts := make([]string, 0, len(runs))
	for _, value := range runs {
		parts = append(parts, strconv.FormatFloat(value, 'f', 0, 64))
	}
	return "[" + strings.Join(parts, ",") + "]"
}

// Runtimes are kept as whole seconds. Ordering only needs to know which
// plugins are slow, and sub-second precision on a measurement that varies by
// tens of seconds between runs is noise dressed up as data.
func formatSeconds(value float64, measured bool) string {
	if !measured {
		return ""
	}
	return strconv.FormatFloat(value, 'f', 0, 64)
}

// loadStats reads the statistics file. A missing file is not an error: the run
// simply starts with no history and writes one at the end.
func loadStats(path string) (*statsTable, error) {
	table := newStatsTable()
	table.path = path
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return table, nil
		}
		return table, err
	}
	table.existed = true
	defer file.Close()

	reader := csv.NewReader(file)
	reader.FieldsPerRecord = -1
	records, err := reader.ReadAll()
	if err != nil {
		return table, err
	}
	if len(records) == 0 {
		return table, nil
	}

	index := map[string]int{}
	for i, name := range records[0] {
		index[name] = i
	}
	get := func(row []string, name string) string {
		if i, ok := index[name]; ok && i < len(row) {
			return row[i]
		}
		return ""
	}
	number := func(row []string, name string) float64 {
		value, _ := strconv.ParseFloat(strings.TrimSpace(get(row, name)), 64)
		return value
	}

	for _, row := range records[1:] {
		name := get(row, "FullName")
		if name == "" {
			continue
		}
		// Only Default and AllRuns are read; the rest are derived from
		// AllRuns when written, so stale values in the file are corrected
		// rather than carried forward.
		stat := &pluginStat{
			def:  math.Round(number(row, "Default")),
			runs: parseRuns(get(row, "AllRuns")),
		}
		table.order = append(table.order, name)
		table.rows[name] = stat
	}
	return table, nil
}

// weight is the ordering key for one plugin. A plugin absent from the file has
// never been seen at all, so it sorts first like any other unknown cost.
func (t *statsTable) weight(module string) float64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	if stat, ok := t.rows[module]; ok {
		return stat.weight()
	}
	return unknownRuntime
}

// record adds one successful run, creating the plugin's row if it is new.
func (t *statsTable) record(module string, seconds float64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	stat, ok := t.rows[module]
	if !ok {
		stat = &pluginStat{def: unknownRuntime}
		t.rows[module] = stat
		t.order = append(t.order, module)
	}
	stat.record(seconds)
}

// save rewrites the file through a temporary copy, so an interrupted write
// cannot destroy the accumulated history.
func (t *statsTable) save(path string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	temp := path + partialSuffix
	file, err := os.Create(temp)
	if err != nil {
		return err
	}
	writer := csv.NewWriter(file)
	if err := writer.Write(statsFields); err != nil {
		file.Close()
		os.Remove(temp)
		return err
	}
	for _, name := range t.order {
		stat := t.rows[name]
		row := []string{name, formatSeconds(stat.def, stat.def > 0), "", "", "", "",
			formatRuns(stat.runs)}
		if stat.measured() {
			row[2] = formatSeconds(stat.last(), true)
			row[3] = formatSeconds(stat.best(), true)
			row[4] = formatSeconds(stat.worst(), true)
			row[5] = formatSeconds(stat.average(), true)
		}
		if err := writer.Write(row); err != nil {
			file.Close()
			os.Remove(temp)
			return err
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		file.Close()
		os.Remove(temp)
		return err
	}
	if err := file.Close(); err != nil {
		os.Remove(temp)
		return err
	}
	return os.Rename(temp, path)
}

// ---------------------------------------------------------------------------
// Results already in the output directory
// ---------------------------------------------------------------------------

// existingOutputs returns the modules whose output file is already present.
//
// Checked in full before anything runs, rather than as each module is about to
// write. Discovering the clash part-way would leave a half-overwritten set --
// worse than either refusing or proceeding. Every path is known up front, so
// there is no reason to find out late.
//
// Only the final output file counts. A leftover .partial is the residue of a killed
// run, not a result, and is replaced without ceremony.
func existingOutputs(cfg config, modules []string) []string {
	var existing []string
	for _, module := range modules {
		if _, err := os.Stat(outputPath(cfg, module)); err == nil {
			existing = append(existing, module)
		}
	}
	return existing
}

// applyExistingPolicy decides what to do about results already on disk, and
// returns the modules that should actually run.
func applyExistingPolicy(cfg config, modules []string) []string {
	existing := existingOutputs(cfg, modules)
	if len(existing) == 0 {
		return modules
	}

	switch {
	case cfg.resume:
		fmt.Printf("Resuming: %d of %d module(s) already have output and will be skipped\n",
			len(existing), len(modules))
		return without(modules, existing)
	case cfg.force:
		fmt.Printf("Overwriting output for %d of %d module(s)\n", len(existing), len(modules))
		return modules
	}

	fmt.Fprintf(os.Stderr, "%d of %d module(s) already have output in %s:\n",
		len(existing), len(modules), cfg.outputDir)
	for index, module := range existing {
		if index == 5 {
			fmt.Fprintf(os.Stderr, "  ... and %d more\n", len(existing)-5)
			break
		}
		fmt.Fprintf(os.Stderr, "  %s\n", filepath.Base(outputPath(cfg, module)))
	}
	fmt.Fprintln(os.Stderr, "Refusing to overwrite. Use --resume to run only what is missing,")
	fmt.Fprintln(os.Stderr, "--force to replace them, or choose a different -o directory.")
	os.Exit(1)
	return nil
}

// ---------------------------------------------------------------------------
// Warming the symbol cache
// ---------------------------------------------------------------------------

// Volatility writes a downloaded symbol table straight to its final path with
// no locking, so several processes starting at once on an image whose symbols
// are not yet on disk will truncate the file under one another. The losers
// fail with EOFError / LZMAError / InvalidAddressException and a different
// set of them fails each run. Fetching the symbols once, serially, removes
// the condition entirely: afterwards every process only reads.
//
// Plugins tried in order; the first that exits 0 wins, and the others fail
// fast because they do not match the image's operating system.
//
// These are chosen for what they require, not for being quick. Warming with
// the fastest plugin is the obvious idea and it does not work: measured
// against a Windows image with the symbols deleted, the two fastest plugins
// download nothing at all -- frameworkinfo.FrameworkInfo (0.6s) and
// isfinfo.IsfInfo (0.8s) never touch the image -- so such a warmup is a silent
// no-op that leaves the race intact.
//
// If this list is ever generated rather than written out, select on
// NeedsKernel and BulkSupport in plugins.csv, which is exactly the property
// required, and never on runtime.
var warmupCandidates = []string{
	"windows.info.Info",
	"linux.pslist.PsList",
	"mac.pslist.PsList",
}

// warmSymbolCache runs a single plugin to completion before anything runs in
// parallel. Its output is discarded: the point is the side effect of fetching
// the symbol tables, not the rows. A failure is reported but not fatal, since
// the batch may still work -- it just runs exposed to the race.
func warmSymbolCache(cfg config) {
	candidates := warmupCandidates
	if cfg.warmupModule != "" {
		candidates = []string{cfg.warmupModule}
	}

	for _, module := range candidates {
		start := time.Now()
		var stderr stderrTail
		cmd := exec.Command(cfg.volatilityPath, "-f", cfg.memoryImage, "-r", cfg.renderer, module)
		cmd.Stdout = nil // Discarded; this run exists for its side effect
		cmd.Stderr = &stderr
		if err := cmd.Run(); err == nil {
			fmt.Printf("Symbol cache warmed by %s in %.2f seconds\n",
				module, time.Since(start).Seconds())
			return
		}
		if cfg.debug {
			fmt.Printf("!    [warmup] %s did not run: %s\n", module, stderr.summary())
		}
	}
	fmt.Printf("!--- Warning: could not warm the symbol cache (tried %s).\n",
		strings.Join(candidates, ", "))
	fmt.Printf("!--- Modules needing symbols may fail unpredictably; -w sets the module to use.\n")
}

// ---------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------

// workerLimit is how many plugins may run at once: one per logical CPU, less
// one, and never below one.
func workerLimit() int {
	n := runtime.NumCPU() - 1
	if n < 1 {
		n = 1
	}
	return n
}

// runAll runs every module, keeping at most limit of them in flight. It blocks
// until all have finished.
// runAll runs every module, keeping at most limit of them in flight, and
// returns how many failed.
func runAll(cfg config, modules []string, stats *statsTable, limit int) int {
	sem := make(chan struct{}, limit) // Limits concurrency
	var wg sync.WaitGroup
	var failures atomic.Int64

	for _, module := range modules {
		sem <- struct{}{} // Acquire a spot in the semaphore
		wg.Add(1)
		go func(module string) {
			// Deferred here rather than inside runModule, and registered
			// first so it runs last. runModule used to signal Done itself,
			// which meant wg.Wait could return -- and the failure count be
			// read -- before this goroutine had finished counting the
			// failure or released its slot.
			defer wg.Done()
			defer func() { <-sem }() // Release the spot in the semaphore

			if !runModule(cfg, module, stats) {
				failures.Add(1)
			}
		}(module)
	}
	wg.Wait()
	return int(failures.Load())
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

func main() {
	cfg := parseFlags()

	if err := os.MkdirAll(cfg.outputDir, 0755); err != nil {
		fmt.Printf("Error creating output directory: %v\n", err)
		os.Exit(1)
	}

	// The inventory is loaded first: it is what -t selects from, and what a
	// missing statistics file is seeded from.
	var inventory []pluginRow
	if cfg.target != "" {
		rows, err := loadPlugins(cfg.pluginsFile)
		if err != nil {
			// A missing inventory is the recoverable case and gets told how to
			// recover. An unreadable or malformed one is a different problem
			// and should say so rather than claim the file is absent.
			if os.IsNotExist(err) {
				fmt.Printf("%s missing, run vol_plugin_inventory.py or specify a list with -m\n",
					cfg.pluginsFile)
			} else {
				fmt.Printf("Error reading plugin inventory: %v\n", err)
			}
			os.Exit(1)
		}
		inventory = rows
	} else if rows, err := loadPlugins(cfg.pluginsFile); err == nil {
		// Optional with -m: it supplies the flag list for the argument prompt
		// and the plugin names for seeding, but the run does not need it.
		inventory = rows
	}
	moduleFlags := flagsByModule(inventory)

	var stats *statsTable
	if !cfg.skipStats {
		loaded, err := loadStats(cfg.statsFile)
		if err != nil {
			fmt.Printf("!--- Warning: could not read %s: %v\n", cfg.statsFile, err)
			fmt.Printf("!--- Continuing without runtime statistics.\n")
		} else {
			stats = loaded
			if !loaded.existed {
				fmt.Printf("!--- %s not found, plugins will be run in alphabetical order\n",
					cfg.statsFile)
			}
			// Whether the file was absent or merely out of date, every plugin
			// the inventory knows about gets a row before anything runs.
			if added := loaded.seedMissing(pluginNames(inventory)); added > 0 && loaded.existed {
				fmt.Printf("Added %d plugin(s) new to %s\n", added, cfg.statsFile)
			}
			// With no inventory there is nothing to seed from, so the file
			// being written covers only this run's modules. Worth saying: it
			// looks like a stats file but is missing almost every plugin.
			if !loaded.existed && len(inventory) == 0 {
				fmt.Printf("!--- %s is unreadable too, so the new statistics file will cover\n", cfg.pluginsFile)
				fmt.Printf("!--- only the modules in this run, not every plugin.\n")
			}
		}
	}

	var modules []string
	if cfg.target != "" {
		var err error
		if modules, err = selectModules(inventory, cfg.target); err != nil {
			fmt.Printf("Error selecting modules: %v\n", err)
			os.Exit(1)
		}
		// Only a generated list is reordered. A list given with -m is left in
		// the order it was written, which the author may have chosen.
		orderByRuntime(modules, stats)
		fmt.Printf("Selected %d modules for target %s from %s\n",
			len(modules), cfg.target, cfg.pluginsFile)
	} else {
		var err error
		if modules, err = readModules(cfg.modulesFile); err != nil {
			fmt.Printf("Error reading modules file: %v\n", err)
			os.Exit(1)
		}
	}

	// A module list may name something the inventory does not cover.
	if stats != nil {
		stats.seedMissing(modules)
	}

	// Before the key press monitor starts: both read stdin.
	modules, cfg.extraArgs = resolveArguments(modules, moduleFlags)
	if len(modules) == 0 {
		fmt.Println("No modules left to run.")
		os.Exit(1)
	}

	// Before the warmup: no reason to spend time fetching symbols for a run
	// that is about to be refused.
	modules = applyExistingPolicy(cfg, modules)
	if len(modules) == 0 {
		fmt.Println("Nothing to do: every module already has output.")
		return
	}

	limit := workerLimit()
	fmt.Printf("Using up to %d goroutines\n", limit)

	totalStart := time.Now()
	if !cfg.skipWarmup {
		warmSymbolCache(cfg)
	}

	go monitorKeyPress(cfg.debug)
	failures := runAll(cfg, modules, stats, limit)

	// No save here: each module wrote the file as it finished.

	fmt.Printf("All modules completed in %.2f seconds.\n", time.Since(totalStart).Seconds())

	// A caller that only sees the exit status should still learn that some of
	// the work did not happen.
	if failures > 0 {
		fmt.Printf("%d of %d module(s) failed.\n", failures, len(modules))
		os.Exit(1)
	}
}
