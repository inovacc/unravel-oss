/*
Copyright (c) 2026 Security Research
*/
package transpile

import "github.com/inovacc/unravel-oss/pkg/aihost"

func init() {
	aihost.RegisterAsset(
		aihost.Asset{
			Path: "skills/transpile/rules/cpp/abseil.md",
			Body: `## Abseil to Go Conversion Rules

- Map ` + "`" + `absl::string_view` + "`" + ` to Go ` + "`" + `string` + "`" + ` (Go strings are already lightweight, immutable views).
- Convert ` + "`" + `absl::StrCat(a, b, c)` + "`" + ` to ` + "`" + `fmt.Sprintf("%s%s%s", a, b, c)` + "`" + ` or ` + "`" + `strings.Join([]string{a, b, c}, "")` + "`" + `.
- Replace ` + "`" + `absl::StrSplit(str, ',')` + "`" + ` with ` + "`" + `strings.Split(str, ",")` + "`" + `.
- Map ` + "`" + `absl::StrFormat("x=%d y=%s", x, y)` + "`" + ` to ` + "`" + `fmt.Sprintf("x=%d y=%s", x, y)` + "`" + `.
- Convert ` + "`" + `absl::StatusOr<T>` + "`" + ` to Go multiple returns ` + "`" + `(T, error)` + "`" + ` with ` + "`" + `if err != nil` + "`" + ` checks.
- Replace ` + "`" + `absl::Status` + "`" + ` codes (` + "`" + `absl::OkStatus()` + "`" + `, ` + "`" + `absl::NotFoundError(msg)` + "`" + `) with ` + "`" + `nil` + "`" + ` for OK and ` + "`" + `fmt.Errorf` + "`" + ` or custom error types.
- Map ` + "`" + `absl::Mutex` + "`" + ` / ` + "`" + `absl::MutexLock` + "`" + ` to ` + "`" + `sync.Mutex` + "`" + ` with ` + "`" + `mu.Lock()` + "`" + ` / ` + "`" + `defer mu.Unlock()` + "`" + `.
- Convert ` + "`" + `absl::flat_hash_map<K,V>` + "`" + ` / ` + "`" + `absl::flat_hash_set<K>` + "`" + ` to Go ` + "`" + `map[K]V` + "`" + ` / ` + "`" + `map[K]struct{}` + "`" + `.
- Replace ` + "`" + `absl::Duration` + "`" + ` / ` + "`" + `absl::Time` + "`" + ` with ` + "`" + `time.Duration` + "`" + ` / ` + "`" + `time.Time` + "`" + ` from Go stdlib.
- Map ` + "`" + `absl::Seconds(n)` + "`" + ` / ` + "`" + `absl::Milliseconds(n)` + "`" + ` to ` + "`" + `n * time.Second` + "`" + ` / ` + "`" + `n * time.Millisecond` + "`" + `.
- Convert ` + "`" + `absl::GetFlag(FLAGS_name)` + "`" + ` / ` + "`" + `ABSL_FLAG(type, name, default, help)` + "`" + ` to Go ` + "`" + `flag.String("name", "default", "help")` + "`" + `.
- Replace ` + "`" + `absl::Span<T>` + "`" + ` with Go slices ` + "`" + `[]T` + "`" + ` (slices are already reference types with length and capacity).
- Map ` + "`" + `absl::optional<T>` + "`" + ` to a Go pointer ` + "`" + `*T` + "`" + ` where ` + "`" + `nil` + "`" + ` represents empty.
- Convert ` + "`" + `LOG(INFO) << "msg"` + "`" + ` / ` + "`" + `CHECK(cond)` + "`" + ` to ` + "`" + `slog.Info("msg")` + "`" + ` / ` + "`" + `if !cond { log.Fatal(...) }` + "`" + `.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/cpp/asio.md",
			Body: `## Boost.Asio to Go Conversion Rules

- Map ` + "`" + `boost::asio::io_context` + "`" + ` and its ` + "`" + `run()` + "`" + ` loop to Go's runtime scheduler (goroutines handle concurrency implicitly).
- Convert ` + "`" + `boost::asio::ip::tcp::socket` + "`" + ` to ` + "`" + `net.Conn` + "`" + ` from ` + "`" + `net.Dial("tcp", "host:port")` + "`" + `.
- Replace ` + "`" + `boost::asio::ip::tcp::acceptor` + "`" + ` with ` + "`" + `net.Listen("tcp", ":port")` + "`" + ` and ` + "`" + `listener.Accept()` + "`" + ` in a loop.
- Map ` + "`" + `async_read` + "`" + ` / ` + "`" + `async_write` + "`" + ` with completion handlers to blocking ` + "`" + `conn.Read()` + "`" + ` / ` + "`" + `conn.Write()` + "`" + ` inside goroutines.
- Convert ` + "`" + `boost::asio::steady_timer` + "`" + ` to ` + "`" + `time.NewTimer` + "`" + ` or ` + "`" + `time.After` + "`" + ` with goroutine select.
- Replace ` + "`" + `boost::asio::ip::udp::socket` + "`" + ` with ` + "`" + `net.ListenPacket("udp", addr)` + "`" + ` or ` + "`" + `net.DialUDP` + "`" + `.
- Map ` + "`" + `boost::asio::strand` + "`" + ` (serialized execution) to a single goroutine reading from a channel.
- Convert ` + "`" + `boost::asio::ssl::stream` + "`" + ` to ` + "`" + `tls.Dial` + "`" + ` or ` + "`" + `tls.Client` + "`" + ` with ` + "`" + `crypto/tls` + "`" + ` configuration.
- Replace ` + "`" + `async_connect` + "`" + ` + callback chains with sequential ` + "`" + `net.Dial` + "`" + ` calls in a goroutine.
- Map ` + "`" + `boost::asio::ip::tcp::resolver` + "`" + ` to ` + "`" + `net.LookupHost` + "`" + ` or ` + "`" + `net.ResolveIPAddr` + "`" + `.
- Convert ` + "`" + `boost::asio::signal_set` + "`" + ` to ` + "`" + `signal.Notify(ch, os.Interrupt, syscall.SIGTERM)` + "`" + `.
- Replace ` + "`" + `io_context.post(fn)` + "`" + ` with ` + "`" + `go fn()` + "`" + ` to schedule concurrent work.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/cpp/boost.md",
			Body: `## Boost to Go Conversion Rules

- Map ` + "`" + `boost::optional<T>` + "`" + ` to a Go pointer ` + "`" + `*T` + "`" + ` where ` + "`" + `nil` + "`" + ` represents no value.
- Convert ` + "`" + `boost::filesystem::path` + "`" + ` operations to Go ` + "`" + `filepath` + "`" + ` package functions (` + "`" + `filepath.Join` + "`" + `, ` + "`" + `filepath.Dir` + "`" + `, etc.).
- Replace ` + "`" + `boost::algorithm::string` + "`" + ` functions (` + "`" + `to_upper` + "`" + `, ` + "`" + `to_lower` + "`" + `, ` + "`" + `trim` + "`" + `, ` + "`" + `split` + "`" + `) with ` + "`" + `strings` + "`" + ` package equivalents.
- Map ` + "`" + `boost::lexical_cast<T>(val)` + "`" + ` to ` + "`" + `strconv.Atoi` + "`" + `, ` + "`" + `strconv.ParseFloat` + "`" + `, or ` + "`" + `fmt.Sprintf` + "`" + `.
- Convert ` + "`" + `boost::regex` + "`" + ` to Go ` + "`" + `regexp.Compile` + "`" + ` / ` + "`" + `regexp.MustCompile` + "`" + ` with ` + "`" + `FindString` + "`" + ` / ` + "`" + `ReplaceAllString` + "`" + `.
- Replace ` + "`" + `boost::program_options` + "`" + ` with cobra CLI flags or Go ` + "`" + `flag` + "`" + ` package.
- Map ` + "`" + `boost::date_time` + "`" + ` types to Go ` + "`" + `time.Time` + "`" + `, ` + "`" + `time.Duration` + "`" + `, and ` + "`" + `time.Parse` + "`" + `.
- Convert ` + "`" + `boost::uuid` + "`" + ` to ` + "`" + `github.com/google/uuid` + "`" + ` with ` + "`" + `uuid.New()` + "`" + ` and ` + "`" + `uuid.Parse()` + "`" + `.
- Replace ` + "`" + `boost::thread` + "`" + ` and ` + "`" + `boost::mutex` + "`" + ` with goroutines, ` + "`" + `sync.Mutex` + "`" + `, and ` + "`" + `sync.WaitGroup` + "`" + `.
- Map ` + "`" + `boost::signals2` + "`" + ` to Go channels or callback function fields on structs.
- Convert ` + "`" + `boost::any` + "`" + ` to Go ` + "`" + `any` + "`" + ` (alias for ` + "`" + `interface{}` + "`" + `).
- Replace ` + "`" + `boost::variant` + "`" + ` with Go interfaces or type-switch patterns.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/cpp/c_stdlib.md",
			Body: `## C Standard Library to Go Conversion Rules

### stdio.h
- Map ` + "`" + `printf(fmt, ...)` + "`" + ` to ` + "`" + `fmt.Printf(fmt, ...)` + "`" + ` with format verb translation (` + "`" + `%d` + "`" + `→` + "`" + `%d` + "`" + `, ` + "`" + `%s` + "`" + `→` + "`" + `%s` + "`" + `, ` + "`" + `%f` + "`" + `→` + "`" + `%f` + "`" + `, ` + "`" + `%p` + "`" + `→` + "`" + `%p` + "`" + `, ` + "`" + `%ld` + "`" + `→` + "`" + `%d` + "`" + `, ` + "`" + `%lld` + "`" + `→` + "`" + `%d` + "`" + `, ` + "`" + `%zu` + "`" + `→` + "`" + `%d` + "`" + `).
- Convert ` + "`" + `fprintf(stderr, ...)` + "`" + ` to ` + "`" + `fmt.Fprintf(os.Stderr, ...)` + "`" + `.
- Convert ` + "`" + `fprintf(fp, ...)` + "`" + ` to ` + "`" + `fmt.Fprintf(fp, ...)` + "`" + `.
- Map ` + "`" + `sprintf(buf, fmt, ...)` + "`" + ` and ` + "`" + `snprintf(buf, n, fmt, ...)` + "`" + ` to ` + "`" + `fmt.Sprintf(fmt, ...)` + "`" + `.
- Convert ` + "`" + `scanf(fmt, &vars...)` + "`" + ` to ` + "`" + `fmt.Scanf(fmt, &vars...)` + "`" + `.
- Map ` + "`" + `sscanf(str, fmt, ...)` + "`" + ` to ` + "`" + `fmt.Sscanf(str, fmt, ...)` + "`" + `.
- Convert ` + "`" + `fopen(path, mode)` + "`" + ` to ` + "`" + `os.Open(path)` + "`" + ` (read) or ` + "`" + `os.Create(path)` + "`" + ` (write) or ` + "`" + `os.OpenFile(path, flags, perm)` + "`" + `.
- Map ` + "`" + `fclose(fp)` + "`" + ` to ` + "`" + `fp.Close()` + "`" + ` — use with ` + "`" + `defer` + "`" + `.
- Convert ` + "`" + `fread(buf, size, count, fp)` + "`" + ` to ` + "`" + `fp.Read(buf)` + "`" + `.
- Convert ` + "`" + `fwrite(buf, size, count, fp)` + "`" + ` to ` + "`" + `fp.Write(buf)` + "`" + `.
- Map ` + "`" + `fgets(buf, n, fp)` + "`" + ` to ` + "`" + `bufio.NewScanner(fp)` + "`" + ` with ` + "`" + `scanner.Scan()` + "`" + `.
- Convert ` + "`" + `fputs(str, fp)` + "`" + ` to ` + "`" + `fmt.Fprint(fp, str)` + "`" + `.
- Map ` + "`" + `fseek(fp, offset, whence)` + "`" + ` to ` + "`" + `fp.Seek(offset, whence)` + "`" + `.
- Convert ` + "`" + `ftell(fp)` + "`" + ` to ` + "`" + `fp.Seek(0, io.SeekCurrent)` + "`" + `.
- Map ` + "`" + `fflush(fp)` + "`" + ` to ` + "`" + `fp.Sync()` + "`" + `.
- Convert ` + "`" + `tmpfile()` + "`" + ` to ` + "`" + `os.CreateTemp("", "prefix")` + "`" + `.
- Map ` + "`" + `puts(str)` + "`" + ` to ` + "`" + `fmt.Println(str)` + "`" + `.
- Convert ` + "`" + `getchar()` + "`" + ` to ` + "`" + `bufio.NewReader(os.Stdin).ReadByte()` + "`" + `.
- Map ` + "`" + `putchar(c)` + "`" + ` to ` + "`" + `fmt.Printf("%c", c)` + "`" + `.
- Convert ` + "`" + `perror(msg)` + "`" + ` to ` + "`" + `fmt.Fprintf(os.Stderr, "%s: %v\n", msg, err)` + "`" + `.

### stdlib.h
- Convert ` + "`" + `malloc(size)` + "`" + ` to ` + "`" + `make([]byte, size)` + "`" + ` or ` + "`" + `new(T)` + "`" + ` — Go GC handles deallocation.
- Map ` + "`" + `calloc(count, size)` + "`" + ` to ` + "`" + `make([]T, count)` + "`" + ` (zero-initialized by default in Go).
- Convert ` + "`" + `realloc(ptr, size)` + "`" + ` to ` + "`" + `append(slice, ...)` + "`" + ` or creating a new larger slice and copying.
- Remove ` + "`" + `free(ptr)` + "`" + ` calls — Go's garbage collector manages memory.
- Map ` + "`" + `exit(code)` + "`" + ` to ` + "`" + `os.Exit(code)` + "`" + `.
- Convert ` + "`" + `atoi(str)` + "`" + ` to ` + "`" + `strconv.Atoi(str)` + "`" + ` (returns value and error).
- Map ` + "`" + `atof(str)` + "`" + ` to ` + "`" + `strconv.ParseFloat(str, 64)` + "`" + `.
- Convert ` + "`" + `strtol(str, NULL, base)` + "`" + ` to ` + "`" + `strconv.ParseInt(str, base, 64)` + "`" + `.
- Map ` + "`" + `strtoul(str, NULL, base)` + "`" + ` to ` + "`" + `strconv.ParseUint(str, base, 64)` + "`" + `.
- Convert ` + "`" + `qsort(arr, count, size, cmp)` + "`" + ` to ` + "`" + `sort.Slice(slice, func(i, j int) bool { ... })` + "`" + `.
- Map ` + "`" + `abs(n)` + "`" + ` to a manual ` + "`" + `if n < 0 { n = -n }` + "`" + ` or cast to float64 for ` + "`" + `math.Abs` + "`" + `.
- Convert ` + "`" + `getenv(name)` + "`" + ` to ` + "`" + `os.Getenv(name)` + "`" + `.
- Map ` + "`" + `system(cmd)` + "`" + ` to ` + "`" + `exec.Command("sh", "-c", cmd).Run()` + "`" + `.
- Convert ` + "`" + `rand()` + "`" + ` to ` + "`" + `rand.Intn(RAND_MAX)` + "`" + ` from ` + "`" + `math/rand` + "`" + `.
- Map ` + "`" + `srand(seed)` + "`" + ` to ` + "`" + `rand.New(rand.NewSource(seed))` + "`" + `.

### string.h
- Map ` + "`" + `strlen(s)` + "`" + ` to ` + "`" + `len(s)` + "`" + ` for Go strings or ` + "`" + `len(s)` + "`" + ` for ` + "`" + `[]byte` + "`" + `.
- Convert ` + "`" + `strcmp(a, b)` + "`" + ` to ` + "`" + `a == b` + "`" + ` for equality, or ` + "`" + `strings.Compare(a, b)` + "`" + ` for ordering.
- Map ` + "`" + `strncmp(a, b, n)` + "`" + ` to comparing ` + "`" + `a[:n] == b[:n]` + "`" + ` with bounds checks.
- Convert ` + "`" + `strcpy(dst, src)` + "`" + ` to Go string assignment ` + "`" + `dst = src` + "`" + ` or ` + "`" + `copy(dst, src)` + "`" + ` for ` + "`" + `[]byte` + "`" + `.
- Map ` + "`" + `strncpy(dst, src, n)` + "`" + ` to ` + "`" + `copy(dst[:n], src)` + "`" + `.
- Convert ` + "`" + `strcat(dst, src)` + "`" + ` to ` + "`" + `dst + src` + "`" + ` for strings or ` + "`" + `append(dst, src...)` + "`" + ` for ` + "`" + `[]byte` + "`" + `.
- Map ` + "`" + `strstr(haystack, needle)` + "`" + ` to ` + "`" + `strings.Contains(haystack, needle)` + "`" + ` or ` + "`" + `strings.Index(haystack, needle)` + "`" + `.
- Convert ` + "`" + `strchr(s, c)` + "`" + ` to ` + "`" + `strings.IndexByte(s, c)` + "`" + `.
- Map ` + "`" + `strrchr(s, c)` + "`" + ` to ` + "`" + `strings.LastIndexByte(s, c)` + "`" + `.
- Convert ` + "`" + `strtok(str, delim)` + "`" + ` to ` + "`" + `strings.Split(str, delim)` + "`" + `.
- Map ` + "`" + `memcpy(dst, src, n)` + "`" + ` to ` + "`" + `copy(dst[:n], src[:n])` + "`" + `.
- Convert ` + "`" + `memmove(dst, src, n)` + "`" + ` to ` + "`" + `copy(dst[:n], src[:n])` + "`" + ` (Go's copy handles overlap).
- Map ` + "`" + `memset(ptr, val, n)` + "`" + ` to a loop or ` + "`" + `bytes.Repeat([]byte{val}, n)` + "`" + `.
- Convert ` + "`" + `memcmp(a, b, n)` + "`" + ` to ` + "`" + `bytes.Equal(a[:n], b[:n])` + "`" + ` or ` + "`" + `bytes.Compare(a[:n], b[:n])` + "`" + `.

### math.h
- Map C math functions directly to Go ` + "`" + `math` + "`" + ` package equivalents: ` + "`" + `sin` + "`" + `→` + "`" + `math.Sin` + "`" + `, ` + "`" + `cos` + "`" + `→` + "`" + `math.Cos` + "`" + `, ` + "`" + `tan` + "`" + `→` + "`" + `math.Tan` + "`" + `, ` + "`" + `sqrt` + "`" + `→` + "`" + `math.Sqrt` + "`" + `, ` + "`" + `pow` + "`" + `→` + "`" + `math.Pow` + "`" + `, ` + "`" + `log` + "`" + `→` + "`" + `math.Log` + "`" + `, ` + "`" + `log10` + "`" + `→` + "`" + `math.Log10` + "`" + `, ` + "`" + `exp` + "`" + `→` + "`" + `math.Exp` + "`" + `, ` + "`" + `ceil` + "`" + `→` + "`" + `math.Ceil` + "`" + `, ` + "`" + `floor` + "`" + `→` + "`" + `math.Floor` + "`" + `, ` + "`" + `fabs` + "`" + `→` + "`" + `math.Abs` + "`" + `, ` + "`" + `fmod` + "`" + `→` + "`" + `math.Mod` + "`" + `, ` + "`" + `round` + "`" + `→` + "`" + `math.Round` + "`" + `.
- Convert ` + "`" + `M_PI` + "`" + ` to ` + "`" + `math.Pi` + "`" + ` and ` + "`" + `M_E` + "`" + ` to ` + "`" + `math.E` + "`" + `.

### time.h
- Convert ` + "`" + `time(NULL)` + "`" + ` to ` + "`" + `time.Now().Unix()` + "`" + `.
- Map ` + "`" + `clock()` + "`" + ` to ` + "`" + `time.Now()` + "`" + ` for measuring elapsed time.
- Convert ` + "`" + `difftime(t2, t1)` + "`" + ` to ` + "`" + `t2.Sub(t1)` + "`" + ` using ` + "`" + `time.Duration` + "`" + `.
- Map ` + "`" + `strftime(buf, size, fmt, tm)` + "`" + ` to ` + "`" + `t.Format(layout)` + "`" + ` using Go layout strings.
- Convert ` + "`" + `sleep(seconds)` + "`" + ` to ` + "`" + `time.Sleep(time.Duration(seconds) * time.Second)` + "`" + `.

### ctype.h
- Map ` + "`" + `isalpha(c)` + "`" + ` to ` + "`" + `unicode.IsLetter(rune(c))` + "`" + `.
- Convert ` + "`" + `isdigit(c)` + "`" + ` to ` + "`" + `unicode.IsDigit(rune(c))` + "`" + `.
- Map ` + "`" + `isspace(c)` + "`" + ` to ` + "`" + `unicode.IsSpace(rune(c))` + "`" + `.
- Convert ` + "`" + `toupper(c)` + "`" + ` to ` + "`" + `unicode.ToUpper(rune(c))` + "`" + `.
- Map ` + "`" + `tolower(c)` + "`" + ` to ` + "`" + `unicode.ToLower(rune(c))` + "`" + `.
- Convert ` + "`" + `isalnum(c)` + "`" + ` to ` + "`" + `unicode.IsLetter(rune(c)) || unicode.IsDigit(rune(c))` + "`" + `.

### stdarg.h
- Convert variadic functions using ` + "`" + `va_list` + "`" + `/` + "`" + `va_start` + "`" + `/` + "`" + `va_arg` + "`" + `/` + "`" + `va_end` + "`" + ` to Go variadic functions using ` + "`" + `...Type` + "`" + `.
- Map ` + "`" + `va_list ap; va_start(ap, last); T val = va_arg(ap, T); va_end(ap);` + "`" + ` to ` + "`" + `func f(last T, args ...any)` + "`" + `.

### errno.h / error handling
- Convert ` + "`" + `errno` + "`" + `-based error checking to Go error returns.
- Map ` + "`" + `if (result == -1) { perror("msg"); }` + "`" + ` to ` + "`" + `if err != nil { return fmt.Errorf("msg: %w", err) }` + "`" + `.
- Convert ` + "`" + `strerror(errno)` + "`" + ` to ` + "`" + `err.Error()` + "`" + `.

### signal.h
- Convert ` + "`" + `signal(SIGINT, handler)` + "`" + ` to ` + "`" + `signal.Notify(ch, os.Interrupt)` + "`" + ` with a goroutine listening on the channel.
- Map ` + "`" + `raise(sig)` + "`" + ` to ` + "`" + `syscall.Kill(syscall.Getpid(), sig)` + "`" + `.

### assert.h
- Convert ` + "`" + `assert(expr)` + "`" + ` to an ` + "`" + `if !expr { panic("assertion failed: expr") }` + "`" + ` or use testing assertions in test code.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/cpp/catch2.md",
			Body: `## Catch2 to Go Conversion Rules

- Map ` + "`" + `TEST_CASE("name", "[tag]")` + "`" + ` to Go test functions ` + "`" + `func TestName(t *testing.T)` + "`" + `.
- Convert ` + "`" + `SECTION("name")` + "`" + ` blocks to ` + "`" + `t.Run("name", func(t *testing.T) { ... })` + "`" + ` subtests.
- Replace ` + "`" + `REQUIRE(expr)` + "`" + ` with ` + "`" + `require.True(t, expr)` + "`" + ` from testify, or ` + "`" + `if !expr { t.Fatal(...) }` + "`" + `.
- Map ` + "`" + `REQUIRE(a == b)` + "`" + ` to ` + "`" + `require.Equal(t, expected, actual)` + "`" + ` from testify.
- Convert ` + "`" + `CHECK(expr)` + "`" + ` (non-fatal) to ` + "`" + `assert.True(t, expr)` + "`" + ` from testify, or ` + "`" + `if !expr { t.Error(...) }` + "`" + `.
- Replace ` + "`" + `REQUIRE_THROWS_AS(expr, ExType)` + "`" + ` with ` + "`" + `require.Panics(t, func() { expr })` + "`" + ` or check returned ` + "`" + `error` + "`" + ` type.
- Map ` + "`" + `REQUIRE_NOTHROW(expr)` + "`" + ` to ` + "`" + `require.NotPanics(t, func() { expr })` + "`" + `.
- Convert ` + "`" + `REQUIRE_THAT(val, Catch::Matchers::Contains("sub"))` + "`" + ` to ` + "`" + `require.Contains(t, val, "sub")` + "`" + `.
- Replace ` + "`" + `GENERATE(values(1,2,3))` + "`" + ` parameterized tests with table-driven test patterns using ` + "`" + `[]struct{...}` + "`" + `.
- Map ` + "`" + `BENCHMARK("name")` + "`" + ` to Go benchmark functions ` + "`" + `func BenchmarkName(b *testing.B) { for i := 0; i < b.N; i++ { ... } }` + "`" + `.
- Convert ` + "`" + `INFO("context")` + "`" + ` to ` + "`" + `t.Log("context")` + "`" + ` for diagnostic output on failure.
- Replace ` + "`" + `Catch::Approx(val)` + "`" + ` floating-point comparisons with ` + "`" + `require.InDelta(t, expected, actual, delta)` + "`" + `.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/cpp/curl.md",
			Body: `## libcurl to Go Conversion Rules

- Map ` + "`" + `curl_easy_init()` + "`" + ` + ` + "`" + `curl_easy_setopt` + "`" + ` + ` + "`" + `curl_easy_perform` + "`" + ` to ` + "`" + `http.NewRequest` + "`" + ` + ` + "`" + `http.Client.Do(req)` + "`" + `.
- Convert ` + "`" + `CURLOPT_URL` + "`" + ` to the URL parameter of ` + "`" + `http.NewRequest(method, url, body)` + "`" + `.
- Replace ` + "`" + `CURLOPT_POST` + "`" + ` / ` + "`" + `CURLOPT_POSTFIELDS` + "`" + ` with ` + "`" + `http.NewRequest("POST", url, bytes.NewReader(data))` + "`" + `.
- Map ` + "`" + `CURLOPT_HTTPHEADER` + "`" + ` (linked list of headers) to ` + "`" + `req.Header.Set("Key", "Value")` + "`" + ` calls.
- Convert ` + "`" + `CURLOPT_WRITEFUNCTION` + "`" + ` / ` + "`" + `CURLOPT_WRITEDATA` + "`" + ` callback to reading ` + "`" + `resp.Body` + "`" + ` via ` + "`" + `io.ReadAll(resp.Body)` + "`" + `.
- Replace ` + "`" + `CURLOPT_TIMEOUT` + "`" + ` with ` + "`" + `http.Client{Timeout: n * time.Second}` + "`" + `.
- Map ` + "`" + `CURLOPT_FOLLOWLOCATION` + "`" + ` to the default ` + "`" + `http.Client` + "`" + ` behavior (follows redirects by default; use ` + "`" + `CheckRedirect` + "`" + ` to disable).
- Convert ` + "`" + `CURLOPT_USERPWD` + "`" + ` basic auth to ` + "`" + `req.SetBasicAuth(user, pass)` + "`" + `.
- Replace ` + "`" + `CURLOPT_SSL_VERIFYPEER = 0` + "`" + ` with ` + "`" + `http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}` + "`" + ` -- add a security warning comment.
- Map ` + "`" + `CURLOPT_UPLOAD` + "`" + ` + ` + "`" + `CURLOPT_READDATA` + "`" + ` file upload to ` + "`" + `http.NewRequest("PUT", url, file)` + "`" + ` with the file as ` + "`" + `io.Reader` + "`" + `.
- Convert ` + "`" + `curl_formadd` + "`" + ` / ` + "`" + `CURLOPT_HTTPPOST` + "`" + ` multipart form to ` + "`" + `multipart.NewWriter(body)` + "`" + ` with ` + "`" + `writer.CreateFormFile` + "`" + `.
- Replace ` + "`" + `curl_easy_getinfo(CURLINFO_RESPONSE_CODE)` + "`" + ` with ` + "`" + `resp.StatusCode` + "`" + `.
- Map ` + "`" + `curl_multi_perform` + "`" + ` concurrent requests to goroutines each performing ` + "`" + `http.Client.Do(req)` + "`" + ` with ` + "`" + `sync.WaitGroup` + "`" + `.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/cpp/eigen.md",
			Body: `## Eigen to Go Conversion Rules

- Map ` + "`" + `Eigen::MatrixXd` + "`" + ` to ` + "`" + `mat.Dense` + "`" + ` from ` + "`" + `gonum.org/v1/gonum/mat` + "`" + ` via ` + "`" + `mat.NewDense(rows, cols, data)` + "`" + `.
- Convert ` + "`" + `Eigen::VectorXd` + "`" + ` to ` + "`" + `mat.VecDense` + "`" + ` from gonum via ` + "`" + `mat.NewVecDense(size, data)` + "`" + `.
- Replace ` + "`" + `matrix * vector` + "`" + ` multiplication with ` + "`" + `result.MulVec(matrix, vector)` + "`" + ` using gonum receiver methods.
- Map ` + "`" + `matrix.transpose()` + "`" + ` to ` + "`" + `result.T()` + "`" + ` (returns a ` + "`" + `mat.Matrix` + "`" + ` view, no copy).
- Convert ` + "`" + `matrix.inverse()` + "`" + ` to ` + "`" + `result.Inverse(matrix)` + "`" + ` with error checking for singular matrices.
- Replace ` + "`" + `matrix.determinant()` + "`" + ` with ` + "`" + `mat.Det(matrix)` + "`" + ` from gonum.
- Map ` + "`" + `Eigen::SelfAdjointEigenSolver` + "`" + ` to ` + "`" + `mat.Eigen{}` + "`" + ` with ` + "`" + `eigen.Factorize(matrix, mat.EigenRight)` + "`" + `.
- Convert ` + "`" + `matrix.svd()` + "`" + ` to ` + "`" + `mat.SVD{}` + "`" + ` with ` + "`" + `svd.Factorize(matrix, mat.SVDFull)` + "`" + `.
- Replace ` + "`" + `Eigen::Matrix3d::Identity()` + "`" + ` with ` + "`" + `eye := mat.NewDiagDense(3, []float64{1, 1, 1})` + "`" + `.
- Map ` + "`" + `matrix.block(i, j, rows, cols)` + "`" + ` to ` + "`" + `matrix.Slice(i, i+rows, j, j+cols)` + "`" + `.
- Convert element access ` + "`" + `matrix(i, j)` + "`" + ` to ` + "`" + `matrix.At(i, j)` + "`" + ` and ` + "`" + `matrix.Set(i, j, val)` + "`" + `.
- Replace ` + "`" + `Eigen::Map<MatrixXd>(data, rows, cols)` + "`" + ` with ` + "`" + `mat.NewDense(rows, cols, data)` + "`" + ` (gonum uses the provided slice directly).
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/cpp/fmt.md",
			Body: `## fmtlib to Go Conversion Rules

- Map ` + "`" + `#include <fmt/core.h>` + "`" + ` to ` + "`" + `import "fmt"` + "`" + `.
- Convert ` + "`" + `fmt::print("Hello, {}!\n", name)` + "`" + ` to ` + "`" + `fmt.Printf("Hello, %s!\n", name)` + "`" + `.
- Replace ` + "`" + `fmt::format("x={}, y={}", x, y)` + "`" + ` with ` + "`" + `fmt.Sprintf("x=%v, y=%v", x, y)` + "`" + `.
- Map ` + "`" + `fmt::println("msg")` + "`" + ` to ` + "`" + `fmt.Println("msg")` + "`" + `.
- Convert ` + "`" + `fmt::format("{:.2f}", val)` + "`" + ` to ` + "`" + `fmt.Sprintf("%.2f", val)` + "`" + `.
- Replace ` + "`" + `fmt::format("{:d}", n)` + "`" + ` to ` + "`" + `fmt.Sprintf("%d", n)` + "`" + `.
- Map ` + "`" + `fmt::format("{:x}", n)` + "`" + ` to ` + "`" + `fmt.Sprintf("%x", n)` + "`" + ` for hexadecimal.
- Convert ` + "`" + `fmt::format("{:>10}", s)` + "`" + ` (right-align) to ` + "`" + `fmt.Sprintf("%10s", s)` + "`" + `.
- Replace ` + "`" + `fmt::format("{:<10}", s)` + "`" + ` (left-align) to ` + "`" + `fmt.Sprintf("%-10s", s)` + "`" + `.
- Map ` + "`" + `fmt::format("{:05d}", n)` + "`" + ` (zero-padded) to ` + "`" + `fmt.Sprintf("%05d", n)` + "`" + `.
- Convert ` + "`" + `fmt::format_to(out, ...)` + "`" + ` to ` + "`" + `fmt.Fprintf(writer, ...)` + "`" + `.
- Replace ` + "`" + `fmt::to_string(val)` + "`" + ` with ` + "`" + `fmt.Sprint(val)` + "`" + ` or ` + "`" + `strconv.Itoa(val)` + "`" + ` for integers.
- Map custom ` + "`" + `fmt::formatter<T>` + "`" + ` specializations to implementing the ` + "`" + `fmt.Stringer` + "`" + ` interface (` + "`" + `String() string` + "`" + `).
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/cpp/googletest.md",
			Body: `## Google Test/Mock to Go Conversion Rules

- Map ` + "`" + `TEST(SuiteName, TestName)` + "`" + ` to ` + "`" + `func TestSuiteName_TestName(t *testing.T)` + "`" + `.
- Convert ` + "`" + `TEST_F(FixtureClass, TestName)` + "`" + ` to a test function with setup/teardown using ` + "`" + `t.Cleanup(fn)` + "`" + `.
- Replace ` + "`" + `EXPECT_EQ(expected, actual)` + "`" + ` with ` + "`" + `assert.Equal(t, expected, actual)` + "`" + ` from testify.
- Map ` + "`" + `ASSERT_EQ(expected, actual)` + "`" + ` to ` + "`" + `require.Equal(t, expected, actual)` + "`" + ` (fatal on failure).
- Convert ` + "`" + `EXPECT_TRUE(expr)` + "`" + ` / ` + "`" + `EXPECT_FALSE(expr)` + "`" + ` to ` + "`" + `assert.True(t, expr)` + "`" + ` / ` + "`" + `assert.False(t, expr)` + "`" + `.
- Replace ` + "`" + `EXPECT_NEAR(a, b, delta)` + "`" + ` with ` + "`" + `assert.InDelta(t, a, b, delta)` + "`" + `.
- Map ` + "`" + `EXPECT_THROW(stmt, ExType)` + "`" + ` to ` + "`" + `assert.Error(t, err)` + "`" + ` with ` + "`" + `errors.As(err, &target)` + "`" + ` type checking.
- Convert ` + "`" + `EXPECT_THAT(val, testing::HasSubstr("x"))` + "`" + ` to ` + "`" + `assert.Contains(t, val, "x")` + "`" + `.
- Replace ` + "`" + `TEST_P` + "`" + ` parameterized tests with table-driven tests using ` + "`" + `for _, tc := range testCases { t.Run(...) }` + "`" + `.
- Map ` + "`" + `INSTANTIATE_TEST_SUITE_P` + "`" + ` test data to ` + "`" + `[]struct{ name string; ... }` + "`" + ` test case slices.
- Convert ` + "`" + `MOCK_METHOD(RetType, Name, (Args))` + "`" + ` to interface-based mocking with testify ` + "`" + `mock.Mock` + "`" + ` or hand-written stubs.
- Replace ` + "`" + `EXPECT_CALL(mock, Method(_)).WillReturn(val)` + "`" + ` with ` + "`" + `mock.On("Method", mock.Anything).Return(val)` + "`" + `.
- Map ` + "`" + `SetUp()` + "`" + ` / ` + "`" + `TearDown()` + "`" + ` fixture methods to ` + "`" + `t.Cleanup()` + "`" + ` or ` + "`" + `TestMain(m *testing.M)` + "`" + `.
- Convert ` + "`" + `testing::Values(...)` + "`" + ` generators to Go slice literals in table-driven test definitions.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/cpp/grpc.md",
			Body: `## gRPC C++ to Go Conversion Rules

- Map ` + "`" + `grpc::ServerBuilder` + "`" + ` with ` + "`" + `AddListeningPort` + "`" + ` / ` + "`" + `RegisterService` + "`" + ` / ` + "`" + `BuildAndStart` + "`" + ` to ` + "`" + `grpc.NewServer()` + "`" + ` + ` + "`" + `pb.RegisterXServer` + "`" + ` + ` + "`" + `lis, _ := net.Listen; s.Serve(lis)` + "`" + `.
- Convert C++ service implementation classes inheriting ` + "`" + `X::Service` + "`" + ` to Go structs embedding ` + "`" + `pb.UnimplementedXServer` + "`" + `.
- Replace ` + "`" + `grpc::CreateChannel("host:port", creds)` + "`" + ` with ` + "`" + `grpc.NewClient("host:port", grpc.WithTransportCredentials(...))` + "`" + `.
- Map ` + "`" + `std::unique_ptr<X::Stub> stub = X::NewStub(channel)` + "`" + ` to ` + "`" + `client := pb.NewXClient(conn)` + "`" + `.
- Convert ` + "`" + `grpc::ClientContext` + "`" + ` to ` + "`" + `context.Background()` + "`" + ` or ` + "`" + `context.WithTimeout` + "`" + `.
- Replace ` + "`" + `grpc::Status` + "`" + ` return values with Go ` + "`" + `error` + "`" + ` using ` + "`" + `status.Errorf(codes.NotFound, "msg")` + "`" + `.
- Map ` + "`" + `grpc::StatusCode` + "`" + ` enum values to ` + "`" + `codes` + "`" + ` package constants (` + "`" + `codes.OK` + "`" + `, ` + "`" + `codes.NotFound` + "`" + `, ` + "`" + `codes.Internal` + "`" + `).
- Convert ` + "`" + `ServerReaderWriter<Resp, Req>` + "`" + ` bidirectional streaming to ` + "`" + `stream.Send` + "`" + ` / ` + "`" + `stream.Recv` + "`" + ` in concurrent goroutines.
- Replace ` + "`" + `grpc::SslCredentials` + "`" + ` with ` + "`" + `credentials.NewTLS(&tls.Config{...})` + "`" + ` from ` + "`" + `google.golang.org/grpc/credentials` + "`" + `.
- Map ` + "`" + `grpc::ServerUnaryInterceptor` + "`" + ` to ` + "`" + `grpc.UnaryInterceptor(fn)` + "`" + ` server option.
- Convert ` + "`" + `CompletionQueue` + "`" + ` async patterns to blocking calls inside goroutines (Go handles concurrency natively).
- Replace ` + "`" + `grpc::reflection::InitProtoReflectionServerBuilderPlugin()` + "`" + ` with ` + "`" + `reflection.Register(server)` + "`" + `.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/cpp/imgui.md",
			Body: `## Dear ImGui to Go Conversion Rules

- Map ` + "`" + `#include "imgui.h"` + "`" + ` to ` + "`" + `import imgui "github.com/AllenDang/cimgui-go"` + "`" + ` for CGo bindings.
- Convert ` + "`" + `ImGui::CreateContext()` + "`" + ` to ` + "`" + `imgui.CreateContext()` + "`" + ` with defer ` + "`" + `imgui.DestroyContext()` + "`" + `.
- Replace ` + "`" + `ImGui::Begin("Window")` + "`" + ` / ` + "`" + `ImGui::End()` + "`" + ` with ` + "`" + `imgui.BeginV("Window", nil, 0)` + "`" + ` / ` + "`" + `imgui.End()` + "`" + `.
- Map ` + "`" + `ImGui::Text("hello %d", val)` + "`" + ` to ` + "`" + `imgui.Text(fmt.Sprintf("hello %d", val))` + "`" + `.
- Convert ` + "`" + `ImGui::Button("Click")` + "`" + ` to ` + "`" + `if imgui.Button("Click") { ... }` + "`" + ` (returns bool).
- Replace ` + "`" + `ImGui::InputText("label", buf, size)` + "`" + ` with ` + "`" + `imgui.InputText("label", &str)` + "`" + `.
- Map ` + "`" + `ImGui::SliderFloat("val", &f, 0.0f, 1.0f)` + "`" + ` to ` + "`" + `imgui.SliderFloat("val", &f, 0.0, 1.0)` + "`" + `.
- Convert ` + "`" + `ImGui::Checkbox("check", &b)` + "`" + ` to ` + "`" + `imgui.Checkbox("check", &b)` + "`" + `.
- Replace ` + "`" + `ImGui::BeginMenuBar` + "`" + ` / ` + "`" + `ImGui::MenuItem("Open")` + "`" + ` with ` + "`" + `imgui.BeginMenuBar()` + "`" + ` / ` + "`" + `imgui.MenuItem("Open")` + "`" + `.
- Map ` + "`" + `ImGui::SameLine()` + "`" + ` / ` + "`" + `ImGui::Separator()` + "`" + ` to ` + "`" + `imgui.SameLine()` + "`" + ` / ` + "`" + `imgui.Separator()` + "`" + `.
- Convert ImGui + GLFW + OpenGL backend setup to ` + "`" + `github.com/AllenDang/cimgui-go` + "`" + ` backend initialization functions.
- Replace ` + "`" + `ImGui::GetIO().DeltaTime` + "`" + ` with ` + "`" + `imgui.CurrentIO().GetDeltaTime()` + "`" + `.
- Map ` + "`" + `ImGui::StyleColorsDark()` + "`" + ` to ` + "`" + `imgui.StyleColorsDark()` + "`" + `.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/cpp/json.md",
			Body: `## nlohmann/json and RapidJSON to Go Conversion Rules

- Map ` + "`" + `#include <nlohmann/json.hpp>` + "`" + ` to ` + "`" + `import "encoding/json"` + "`" + `.
- Convert ` + "`" + `nlohmann::json j = nlohmann::json::parse(str)` + "`" + ` to ` + "`" + `json.Unmarshal([]byte(str), &target)` + "`" + `.
- Replace ` + "`" + `j.dump()` + "`" + ` / ` + "`" + `j.dump(2)` + "`" + ` with ` + "`" + `json.Marshal(obj)` + "`" + ` / ` + "`" + `json.MarshalIndent(obj, "", "  ")` + "`" + `.
- Map ` + "`" + `j["key"]` + "`" + ` dynamic access to ` + "`" + `map[string]any` + "`" + ` with type assertions, or typed Go structs with ` + "`" + `json:"key"` + "`" + ` tags.
- Convert ` + "`" + `j.at("key").get<int>()` + "`" + ` to struct field access after ` + "`" + `json.Unmarshal` + "`" + ` into a typed struct.
- Replace ` + "`" + `j.contains("key")` + "`" + ` with ` + "`" + `_, ok := m["key"]` + "`" + ` map lookup idiom.
- Map ` + "`" + `j.is_null()` + "`" + ` / ` + "`" + `j.is_string()` + "`" + ` type checks to type assertions ` + "`" + `val, ok := v.(string)` + "`" + `.
- Convert ` + "`" + `nlohmann::json::array()` + "`" + ` / ` + "`" + `nlohmann::json::object()` + "`" + ` construction to Go slice/map literals.
- Replace ` + "`" + `rapidjson::Document d; d.Parse(str)` + "`" + ` with ` + "`" + `json.Unmarshal([]byte(str), &target)` + "`" + `.
- Map ` + "`" + `rapidjson::StringBuffer` + "`" + ` + ` + "`" + `rapidjson::Writer` + "`" + ` to ` + "`" + `json.NewEncoder(writer).Encode(obj)` + "`" + `.
- Convert ` + "`" + `NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(Type, fields...)` + "`" + ` to Go struct with ` + "`" + `json:"field"` + "`" + ` tags.
- Replace ` + "`" + `j.get<std::vector<int>>()` + "`" + ` with unmarshaling into ` + "`" + `[]int` + "`" + ` via ` + "`" + `json.Unmarshal` + "`" + `.
- Map ` + "`" + `json::parse(stream)` + "`" + ` from file/stream to ` + "`" + `json.NewDecoder(reader).Decode(&target)` + "`" + `.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/cpp/opencv.md",
			Body: `## OpenCV to Go Conversion Rules

- Map ` + "`" + `#include <opencv2/opencv.hpp>` + "`" + ` to ` + "`" + `import "gocv.io/x/gocv"` + "`" + `.
- Convert ` + "`" + `cv::Mat` + "`" + ` to ` + "`" + `gocv.Mat` + "`" + ` with ` + "`" + `gocv.NewMat()` + "`" + ` and defer ` + "`" + `mat.Close()` + "`" + ` for cleanup.
- Replace ` + "`" + `cv::imread("file")` + "`" + ` with ` + "`" + `gocv.IMRead("file", gocv.IMReadColor)` + "`" + `.
- Map ` + "`" + `cv::imwrite("file", mat)` + "`" + ` to ` + "`" + `gocv.IMWrite("file", mat)` + "`" + `.
- Convert ` + "`" + `cv::cvtColor(src, dst, cv::COLOR_BGR2GRAY)` + "`" + ` to ` + "`" + `gocv.CvtColor(src, &dst, gocv.ColorBGRToGray)` + "`" + `.
- Replace ` + "`" + `cv::GaussianBlur(src, dst, Size(5,5), 0)` + "`" + ` with ` + "`" + `gocv.GaussianBlur(src, &dst, image.Pt(5,5), 0, 0, gocv.BorderDefault)` + "`" + `.
- Map ` + "`" + `cv::resize(src, dst, Size(w,h))` + "`" + ` to ` + "`" + `gocv.Resize(src, &dst, image.Pt(w,h), 0, 0, gocv.InterpolationLinear)` + "`" + `.
- Convert ` + "`" + `cv::VideoCapture cap(0)` + "`" + ` to ` + "`" + `cap, _ := gocv.VideoCaptureDevice(0)` + "`" + ` with defer ` + "`" + `cap.Close()` + "`" + `.
- Replace ` + "`" + `cap.read(frame)` + "`" + ` with ` + "`" + `cap.Read(&frame)` + "`" + `.
- Map ` + "`" + `cv::CascadeClassifier` + "`" + ` to ` + "`" + `gocv.NewCascadeClassifier()` + "`" + ` with ` + "`" + `classifier.Load("file.xml")` + "`" + `.
- Convert ` + "`" + `cv::threshold(src, dst, thresh, max, type)` + "`" + ` to ` + "`" + `gocv.Threshold(src, &dst, thresh, max, gocv.ThresholdBinary)` + "`" + `.
- Replace ` + "`" + `cv::Canny(src, dst, t1, t2)` + "`" + ` with ` + "`" + `gocv.Canny(src, &dst, t1, t2)` + "`" + `.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/cpp/opengl.md",
			Body: `## OpenGL to Go Conversion Rules

**Warning: Go OpenGL bindings work but are less common for production use. Consider whether the rendering requirements justify porting to Go.**

- Map ` + "`" + `#include <GL/glew.h>` + "`" + ` or ` + "`" + `#include <glad/glad.h>` + "`" + ` to ` + "`" + `import "github.com/go-gl/gl/v4.1-core/gl"` + "`" + ` with ` + "`" + `gl.Init()` + "`" + `.
- Convert GLFW window creation to ` + "`" + `import "github.com/go-gl/glfw/v3.3/glfw"` + "`" + ` with ` + "`" + `glfw.Init()` + "`" + ` and ` + "`" + `glfw.CreateWindow` + "`" + `.
- Replace ` + "`" + `glClearColor(r, g, b, a)` + "`" + ` with ` + "`" + `gl.ClearColor(r, g, b, a)` + "`" + `.
- Map ` + "`" + `glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT)` + "`" + ` to ` + "`" + `gl.Clear(gl.COLOR_BUFFER_BIT | gl.DEPTH_BUFFER_BIT)` + "`" + `.
- Convert ` + "`" + `glGenBuffers(1, &vbo)` + "`" + ` to ` + "`" + `gl.GenBuffers(1, &vbo)` + "`" + `.
- Replace ` + "`" + `glBufferData(GL_ARRAY_BUFFER, size, data, GL_STATIC_DRAW)` + "`" + ` with ` + "`" + `gl.BufferData(gl.ARRAY_BUFFER, size, gl.Ptr(data), gl.STATIC_DRAW)` + "`" + `.
- Map ` + "`" + `glCreateShader` + "`" + ` / ` + "`" + `glShaderSource` + "`" + ` / ` + "`" + `glCompileShader` + "`" + ` to equivalent ` + "`" + `gl.CreateShader` + "`" + ` / ` + "`" + `gl.ShaderSource` + "`" + ` / ` + "`" + `gl.CompileShader` + "`" + ` calls using ` + "`" + `gl.Str(source)` + "`" + ` for C-string conversion.
- Convert ` + "`" + `glDrawArrays(GL_TRIANGLES, 0, count)` + "`" + ` to ` + "`" + `gl.DrawArrays(gl.TRIANGLES, 0, int32(count))` + "`" + `.
- Replace ` + "`" + `glUniformMatrix4fv(loc, 1, false, &mat[0])` + "`" + ` with ` + "`" + `gl.UniformMatrix4fv(loc, 1, false, &mat[0])` + "`" + `.
- Map GLM math library (` + "`" + `glm::mat4` + "`" + `, ` + "`" + `glm::perspective` + "`" + `) to ` + "`" + `github.com/go-gl/mathgl/mgl32` + "`" + ` package.
- Convert the render loop ` + "`" + `while(!glfwWindowShouldClose(window))` + "`" + ` to ` + "`" + `for !window.ShouldClose()` + "`" + `.
- Replace ` + "`" + `glGetError()` + "`" + ` checks with ` + "`" + `gl.GetError()` + "`" + ` and map ` + "`" + `GL_NO_ERROR` + "`" + ` to ` + "`" + `gl.NO_ERROR` + "`" + `.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/cpp/openssl.md",
			Body: `## OpenSSL to Go Conversion Rules

- Map ` + "`" + `#include <openssl/sha.h>` + "`" + ` SHA-256 hashing to ` + "`" + `crypto/sha256` + "`" + ` with ` + "`" + `sha256.Sum256(data)` + "`" + `.
- Convert ` + "`" + `EVP_DigestInit/Update/Final` + "`" + ` streaming hash to ` + "`" + `h := sha256.New(); h.Write(data); h.Sum(nil)` + "`" + `.
- Replace ` + "`" + `HMAC()` + "`" + ` / ` + "`" + `HMAC_Init_ex` + "`" + ` with ` + "`" + `hmac.New(sha256.New, key)` + "`" + ` from ` + "`" + `crypto/hmac` + "`" + `.
- Map ` + "`" + `EVP_EncryptInit_ex` + "`" + ` / ` + "`" + `EVP_EncryptUpdate` + "`" + ` / ` + "`" + `EVP_EncryptFinal_ex` + "`" + ` AES-GCM to ` + "`" + `aes.NewCipher(key)` + "`" + ` + ` + "`" + `cipher.NewGCM(block)` + "`" + ` + ` + "`" + `gcm.Seal(...)` + "`" + `.
- Convert ` + "`" + `EVP_DecryptInit_ex` + "`" + ` AES-GCM decryption to ` + "`" + `gcm.Open(nil, nonce, ciphertext, nil)` + "`" + `.
- Replace ` + "`" + `RSA_generate_key_ex` + "`" + ` with ` + "`" + `rsa.GenerateKey(rand.Reader, bits)` + "`" + ` from ` + "`" + `crypto/rsa` + "`" + `.
- Map ` + "`" + `RSA_public_encrypt` + "`" + ` / ` + "`" + `RSA_private_decrypt` + "`" + ` to ` + "`" + `rsa.EncryptOAEP` + "`" + ` / ` + "`" + `rsa.DecryptOAEP` + "`" + `.
- Convert ` + "`" + `EVP_SignInit` + "`" + ` / ` + "`" + `EVP_SignFinal` + "`" + ` to ` + "`" + `rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hash)` + "`" + `.
- Replace ` + "`" + `PEM_read_bio_X509` + "`" + ` certificate parsing with ` + "`" + `x509.ParseCertificate(der)` + "`" + ` or ` + "`" + `pem.Decode` + "`" + ` + parse.
- Map ` + "`" + `SSL_CTX_new` + "`" + ` / ` + "`" + `SSL_new` + "`" + ` TLS context to ` + "`" + `tls.Config{}` + "`" + ` and ` + "`" + `tls.Dial` + "`" + ` / ` + "`" + `tls.Listen` + "`" + `.
- Convert ` + "`" + `RAND_bytes(buf, n)` + "`" + ` to ` + "`" + `rand.Read(buf)` + "`" + ` from ` + "`" + `crypto/rand` + "`" + `.
- Replace ` + "`" + `EVP_PKEY_derive` + "`" + ` ECDH key exchange with ` + "`" + `ecdh.PrivateKey.ECDH(peerPub)` + "`" + ` from ` + "`" + `crypto/ecdh` + "`" + `.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/cpp/poco.md",
			Body: `## POCO C++ to Go Conversion Rules

- Map ` + "`" + `Poco::Net::HTTPClientSession` + "`" + ` + ` + "`" + `HTTPRequest` + "`" + ` to ` + "`" + `http.NewRequest` + "`" + ` + ` + "`" + `http.Client.Do(req)` + "`" + `.
- Convert ` + "`" + `Poco::Net::HTTPServer` + "`" + ` with ` + "`" + `HTTPRequestHandlerFactory` + "`" + ` to ` + "`" + `http.ListenAndServe` + "`" + ` with ` + "`" + `http.ServeMux` + "`" + `.
- Replace ` + "`" + `Poco::Net::SocketAddress` + "`" + ` with ` + "`" + `net.ResolveTCPAddr` + "`" + ` or string ` + "`" + `"host:port"` + "`" + `.
- Map ` + "`" + `Poco::URI` + "`" + ` parsing to ` + "`" + `url.Parse(rawURL)` + "`" + ` from ` + "`" + `net/url` + "`" + `.
- Convert ` + "`" + `Poco::JSON::Parser` + "`" + ` / ` + "`" + `Poco::JSON::Object` + "`" + ` to ` + "`" + `json.Unmarshal` + "`" + ` into structs or ` + "`" + `map[string]any` + "`" + `.
- Replace ` + "`" + `Poco::File` + "`" + ` / ` + "`" + `Poco::Path` + "`" + ` operations with ` + "`" + `os` + "`" + ` and ` + "`" + `filepath` + "`" + ` package functions.
- Map ` + "`" + `Poco::Logger` + "`" + ` with channels and formatters to ` + "`" + `log/slog` + "`" + ` with appropriate handlers.
- Convert ` + "`" + `Poco::Timer` + "`" + ` / ` + "`" + `Poco::TimerCallback` + "`" + ` to ` + "`" + `time.NewTicker` + "`" + ` or ` + "`" + `time.AfterFunc` + "`" + `.
- Replace ` + "`" + `Poco::Thread` + "`" + ` + ` + "`" + `Poco::Runnable` + "`" + ` with goroutines via ` + "`" + `go func() { ... }()` + "`" + `.
- Map ` + "`" + `Poco::Mutex` + "`" + ` / ` + "`" + `Poco::FastMutex` + "`" + ` to ` + "`" + `sync.Mutex` + "`" + ` or ` + "`" + `sync.RWMutex` + "`" + `.
- Convert ` + "`" + `Poco::TaskManager` + "`" + ` with ` + "`" + `Poco::Task` + "`" + ` subclasses to goroutines coordinated with ` + "`" + `sync.WaitGroup` + "`" + ` and channels.
- Replace ` + "`" + `Poco::DigestEngine` + "`" + ` (MD5/SHA) with ` + "`" + `crypto/md5` + "`" + `, ` + "`" + `crypto/sha256` + "`" + ` from Go stdlib.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/cpp/posix.md",
			Body: `## POSIX API to Go Conversion Rules

### unistd.h
- Convert ` + "`" + `read(fd, buf, count)` + "`" + ` to ` + "`" + `file.Read(buf[:count])` + "`" + `.
- Map ` + "`" + `write(fd, buf, count)` + "`" + ` to ` + "`" + `file.Write(buf[:count])` + "`" + `.
- Convert ` + "`" + `close(fd)` + "`" + ` to ` + "`" + `file.Close()` + "`" + ` — use with ` + "`" + `defer` + "`" + `.
- Map ` + "`" + `fork()` + "`" + ` — Go has no fork equivalent; use goroutines for concurrency.
- Convert ` + "`" + `exec*(path, args)` + "`" + ` to ` + "`" + `exec.Command(path, args...).Run()` + "`" + ` from ` + "`" + `os/exec` + "`" + `.
- Map ` + "`" + `getpid()` + "`" + ` to ` + "`" + `os.Getpid()` + "`" + `.
- Convert ` + "`" + `getppid()` + "`" + ` to ` + "`" + `os.Getppid()` + "`" + `.
- Map ` + "`" + `sleep(seconds)` + "`" + ` to ` + "`" + `time.Sleep(time.Duration(seconds) * time.Second)` + "`" + `.
- Convert ` + "`" + `usleep(microseconds)` + "`" + ` to ` + "`" + `time.Sleep(time.Duration(microseconds) * time.Microsecond)` + "`" + `.
- Map ` + "`" + `access(path, mode)` + "`" + ` to ` + "`" + `os.Stat(path)` + "`" + ` (check error for existence).
- Convert ` + "`" + `chdir(path)` + "`" + ` to ` + "`" + `os.Chdir(path)` + "`" + `.
- Map ` + "`" + `getcwd(buf, size)` + "`" + ` to ` + "`" + `os.Getwd()` + "`" + `.
- Convert ` + "`" + `pipe(fds)` + "`" + ` to ` + "`" + `io.Pipe()` + "`" + ` for in-process or ` + "`" + `os.Pipe()` + "`" + ` for OS-level.
- Map ` + "`" + `dup(fd)` + "`" + ` / ` + "`" + `dup2(oldfd, newfd)` + "`" + ` to ` + "`" + `os.File` + "`" + ` and ` + "`" + `syscall.Dup2` + "`" + `.
- Convert ` + "`" + `unlink(path)` + "`" + ` to ` + "`" + `os.Remove(path)` + "`" + `.
- Map ` + "`" + `rmdir(path)` + "`" + ` to ` + "`" + `os.Remove(path)` + "`" + `.
- Convert ` + "`" + `link(old, new)` + "`" + ` to ` + "`" + `os.Link(old, new)` + "`" + `.
- Map ` + "`" + `symlink(target, linkpath)` + "`" + ` to ` + "`" + `os.Symlink(target, linkpath)` + "`" + `.
- Convert ` + "`" + `readlink(path, buf, size)` + "`" + ` to ` + "`" + `os.Readlink(path)` + "`" + `.
- Map ` + "`" + `isatty(fd)` + "`" + ` to ` + "`" + `term.IsTerminal(int(fd))` + "`" + ` from ` + "`" + `golang.org/x/term` + "`" + `.

### pthread.h
- Convert ` + "`" + `pthread_create(&thread, NULL, func, arg)` + "`" + ` to ` + "`" + `go func(arg)` + "`" + `.
- Map ` + "`" + `pthread_join(thread, NULL)` + "`" + ` to ` + "`" + `sync.WaitGroup.Wait()` + "`" + `.
- Convert ` + "`" + `pthread_mutex_init/lock/unlock/destroy` + "`" + ` to ` + "`" + `sync.Mutex.Lock()/Unlock()` + "`" + `.
- Map ` + "`" + `pthread_rwlock_*` + "`" + ` to ` + "`" + `sync.RWMutex` + "`" + `.
- Convert ` + "`" + `pthread_cond_init/wait/signal/broadcast` + "`" + ` to ` + "`" + `sync.Cond` + "`" + ` or channels.
- Map ` + "`" + `pthread_once(&once, func)` + "`" + ` to ` + "`" + `sync.Once.Do(func)` + "`" + `.
- Convert ` + "`" + `pthread_key_create` + "`" + ` (thread-local storage) to goroutine-local patterns or context values.

### sys/socket.h + arpa/inet.h + netinet/in.h
- Convert ` + "`" + `socket(AF_INET, SOCK_STREAM, 0)` + "`" + ` + ` + "`" + `bind` + "`" + ` + ` + "`" + `listen` + "`" + ` + ` + "`" + `accept` + "`" + ` to ` + "`" + `net.Listen("tcp", addr)` + "`" + ` + ` + "`" + `listener.Accept()` + "`" + `.
- Map ` + "`" + `socket` + "`" + ` + ` + "`" + `connect` + "`" + ` to ` + "`" + `net.Dial("tcp", addr)` + "`" + `.
- Convert ` + "`" + `send(fd, buf, len, flags)` + "`" + ` to ` + "`" + `conn.Write(buf)` + "`" + `.
- Map ` + "`" + `recv(fd, buf, len, flags)` + "`" + ` to ` + "`" + `conn.Read(buf)` + "`" + `.
- Convert ` + "`" + `setsockopt` + "`" + ` to ` + "`" + `net.Dialer` + "`" + ` options or ` + "`" + `syscall.SetsockoptInt` + "`" + `.
- Map ` + "`" + `getsockname/getpeername` + "`" + ` to ` + "`" + `conn.LocalAddr()/RemoteAddr()` + "`" + `.
- Convert ` + "`" + `inet_pton/inet_ntoa` + "`" + ` to ` + "`" + `net.ParseIP/IP.String()` + "`" + `.
- Map ` + "`" + `htons/ntohs/htonl/ntohl` + "`" + ` — Go's ` + "`" + `encoding/binary` + "`" + ` package handles byte order.

### dirent.h
- Convert ` + "`" + `opendir(path)` + "`" + ` + ` + "`" + `readdir(dir)` + "`" + ` + ` + "`" + `closedir(dir)` + "`" + ` loop to ` + "`" + `os.ReadDir(path)` + "`" + `.
- Map ` + "`" + `struct dirent.d_name` + "`" + ` to ` + "`" + `entry.Name()` + "`" + ` from ` + "`" + `os.DirEntry` + "`" + `.

### fcntl.h
- Convert ` + "`" + `open(path, O_RDONLY)` + "`" + ` to ` + "`" + `os.Open(path)` + "`" + `.
- Map ` + "`" + `open(path, O_WRONLY|O_CREAT|O_TRUNC, mode)` + "`" + ` to ` + "`" + `os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)` + "`" + `.
- Convert ` + "`" + `fcntl(fd, F_SETFL, flags)` + "`" + ` to ` + "`" + `syscall.Fcntl` + "`" + ` or platform-specific handling.

### sys/mman.h
- Convert ` + "`" + `mmap(NULL, len, prot, flags, fd, offset)` + "`" + ` to ` + "`" + `syscall.Mmap(fd, offset, len, prot, flags)` + "`" + `.
- Map ` + "`" + `munmap(addr, len)` + "`" + ` to ` + "`" + `syscall.Munmap(data)` + "`" + `.
- Convert ` + "`" + `mprotect(addr, len, prot)` + "`" + ` to ` + "`" + `syscall.Mprotect(data, prot)` + "`" + `.

### sys/stat.h
- Convert ` + "`" + `stat(path, &buf)` + "`" + ` to ` + "`" + `os.Stat(path)` + "`" + ` returning ` + "`" + `os.FileInfo` + "`" + `.
- Map ` + "`" + `fstat(fd, &buf)` + "`" + ` to ` + "`" + `file.Stat()` + "`" + `.
- Convert ` + "`" + `chmod(path, mode)` + "`" + ` to ` + "`" + `os.Chmod(path, mode)` + "`" + `.
- Map ` + "`" + `mkdir(path, mode)` + "`" + ` to ` + "`" + `os.Mkdir(path, mode)` + "`" + ` or ` + "`" + `os.MkdirAll(path, mode)` + "`" + `.
- Convert ` + "`" + `S_ISREG(mode)` + "`" + ` to ` + "`" + `info.Mode().IsRegular()` + "`" + `.
- Map ` + "`" + `S_ISDIR(mode)` + "`" + ` to ` + "`" + `info.IsDir()` + "`" + `.

### dlfcn.h
- Convert ` + "`" + `dlopen(path, RTLD_LAZY)` + "`" + ` to ` + "`" + `plugin.Open(path)` + "`" + ` (limited to Go plugins).
- Map ` + "`" + `dlsym(handle, symbol)` + "`" + ` to ` + "`" + `plugin.Lookup(symbol)` + "`" + `.
- For non-Go shared libraries, use cgo or ` + "`" + `syscall.LoadLibrary` + "`" + ` on Windows.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/cpp/protobuf.md",
			Body: `## Protocol Buffers C++ to Go Conversion Rules

- Map ` + "`" + `#include "myproto.pb.h"` + "`" + ` generated headers to ` + "`" + `import pb "mypackage/proto"` + "`" + ` Go package.
- Convert ` + "`" + `message.SerializeToString(&output)` + "`" + ` to ` + "`" + `proto.Marshal(msg)` + "`" + ` returning ` + "`" + `[]byte, error` + "`" + `.
- Replace ` + "`" + `message.ParseFromString(data)` + "`" + ` with ` + "`" + `proto.Unmarshal(data, msg)` + "`" + `.
- Map ` + "`" + `message.set_field(value)` + "`" + ` setter methods to direct struct field assignment ` + "`" + `msg.Field = value` + "`" + `.
- Convert ` + "`" + `message.field()` + "`" + ` getter methods to direct struct field access ` + "`" + `msg.Field` + "`" + `.
- Replace ` + "`" + `message.has_field()` + "`" + ` presence checks with ` + "`" + `msg.Field != nil` + "`" + ` for pointer/message fields or ` + "`" + `msg.Field != ""` + "`" + ` / ` + "`" + `!= 0` + "`" + ` for scalars.
- Map ` + "`" + `message.mutable_field()` + "`" + ` to direct access of the nested message pointer ` + "`" + `msg.Field` + "`" + ` (auto-allocated).
- Convert ` + "`" + `message.add_repeated_field(val)` + "`" + ` to ` + "`" + `msg.RepeatedField = append(msg.RepeatedField, val)` + "`" + `.
- Replace ` + "`" + `message.repeated_field_size()` + "`" + ` with ` + "`" + `len(msg.RepeatedField)` + "`" + `.
- Map ` + "`" + `google::protobuf::Timestamp` + "`" + ` to ` + "`" + `timestamppb.New(time.Now())` + "`" + ` from ` + "`" + `google.golang.org/protobuf/types/known/timestamppb` + "`" + `.
- Convert ` + "`" + `message.CopyFrom(other)` + "`" + ` to ` + "`" + `proto.Clone(msg)` + "`" + ` for deep copies.
- Replace ` + "`" + `google::protobuf::util::JsonStringToMessage` + "`" + ` with ` + "`" + `protojson.Unmarshal(data, msg)` + "`" + `.
- Map ` + "`" + `google::protobuf::util::MessageToJsonString` + "`" + ` to ` + "`" + `protojson.Marshal(msg)` + "`" + `.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/cpp/qt.md",
			Body: `## Qt to Go Conversion Rules

**Warning: Go GUI libraries (fyne, gio) have significantly fewer features than Qt. Complex Qt applications may require substantial redesign.**

- Map ` + "`" + `QApplication` + "`" + ` + ` + "`" + `QMainWindow` + "`" + ` to ` + "`" + `app := app.New(); w := app.NewWindow("title")` + "`" + ` from ` + "`" + `fyne.io/fyne/v2` + "`" + `.
- Convert ` + "`" + `QPushButton("label")` + "`" + ` to ` + "`" + `widget.NewButton("label", func() { ... })` + "`" + ` in fyne.
- Replace ` + "`" + `QLabel("text")` + "`" + ` with ` + "`" + `widget.NewLabel("text")` + "`" + `.
- Map ` + "`" + `QLineEdit` + "`" + ` to ` + "`" + `widget.NewEntry()` + "`" + ` for single-line text input.
- Convert ` + "`" + `QVBoxLayout` + "`" + ` / ` + "`" + `QHBoxLayout` + "`" + ` to ` + "`" + `container.NewVBox(...)` + "`" + ` / ` + "`" + `container.NewHBox(...)` + "`" + `.
- Replace ` + "`" + `connect(sender, SIGNAL(...), receiver, SLOT(...))` + "`" + ` signal-slot with callback functions passed directly to widget constructors.
- Map ` + "`" + `QFileDialog::getOpenFileName` + "`" + ` to ` + "`" + `dialog.ShowFileOpen(callback, window)` + "`" + `.
- Convert ` + "`" + `QTimer::singleShot(ms, fn)` + "`" + ` to ` + "`" + `time.AfterFunc(duration, fn)` + "`" + `.
- Replace ` + "`" + `QThread` + "`" + ` with goroutines; use channels to send updates back to the UI thread.
- Map ` + "`" + `QSettings` + "`" + ` to a config struct loaded from a JSON/TOML file using ` + "`" + `encoding/json` + "`" + ` or ` + "`" + `github.com/BurntSushi/toml` + "`" + `.
- Convert ` + "`" + `QString` + "`" + ` to Go ` + "`" + `string` + "`" + ` (Go strings are UTF-8 by default).
- Replace ` + "`" + `QListWidget` + "`" + ` / ` + "`" + `QTableWidget` + "`" + ` with ` + "`" + `widget.NewList` + "`" + ` / ` + "`" + `widget.NewTable` + "`" + ` in fyne.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/cpp/sdl.md",
			Body: `## SDL2 to Go Conversion Rules

- Map ` + "`" + `#include <SDL2/SDL.h>` + "`" + ` to ` + "`" + `import "github.com/veandco/go-sdl2/sdl"` + "`" + `.
- Convert ` + "`" + `SDL_Init(SDL_INIT_VIDEO)` + "`" + ` to ` + "`" + `sdl.Init(sdl.INIT_VIDEO)` + "`" + ` with defer ` + "`" + `sdl.Quit()` + "`" + `.
- Replace ` + "`" + `SDL_CreateWindow(...)` + "`" + ` with ` + "`" + `sdl.CreateWindow(title, x, y, w, h, flags)` + "`" + ` with defer ` + "`" + `window.Destroy()` + "`" + `.
- Map ` + "`" + `SDL_CreateRenderer(window, -1, flags)` + "`" + ` to ` + "`" + `sdl.CreateRenderer(window, -1, flags)` + "`" + ` with defer ` + "`" + `renderer.Destroy()` + "`" + `.
- Convert the ` + "`" + `SDL_Event` + "`" + ` poll loop (` + "`" + `SDL_PollEvent(&event)` + "`" + `) to ` + "`" + `for event := sdl.PollEvent(); event != nil; event = sdl.PollEvent()` + "`" + ` with type switch.
- Replace ` + "`" + `SDL_RenderClear` + "`" + ` / ` + "`" + `SDL_RenderPresent` + "`" + ` with ` + "`" + `renderer.Clear()` + "`" + ` / ` + "`" + `renderer.Present()` + "`" + `.
- Map ` + "`" + `SDL_SetRenderDrawColor(r,g,b,a)` + "`" + ` to ` + "`" + `renderer.SetDrawColor(r, g, b, a)` + "`" + `.
- Convert ` + "`" + `SDL_LoadBMP` + "`" + ` / ` + "`" + `SDL_CreateTextureFromSurface` + "`" + ` to ` + "`" + `sdl.LoadBMP(file)` + "`" + ` and ` + "`" + `renderer.CreateTextureFromSurface(surface)` + "`" + `.
- Replace ` + "`" + `SDL_RenderCopy(renderer, texture, src, dst)` + "`" + ` with ` + "`" + `renderer.Copy(texture, src, dst)` + "`" + `.
- Map ` + "`" + `SDL_Delay(ms)` + "`" + ` to ` + "`" + `sdl.Delay(ms)` + "`" + ` or ` + "`" + `time.Sleep(time.Duration(ms) * time.Millisecond)` + "`" + `.
- Convert ` + "`" + `SDL_GetKeyboardState` + "`" + ` to ` + "`" + `sdl.GetKeyboardState()` + "`" + ` returning a byte slice.
- Replace ` + "`" + `SDL_mixer` + "`" + ` audio functions with ` + "`" + `github.com/veandco/go-sdl2/mix` + "`" + ` bindings.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/cpp/sfml.md",
			Body: `## SFML to Go Conversion Rules

**Warning: There is no mature Go SFML binding. Consider using go-sdl2 or Ebitengine as alternatives for 2D game/multimedia applications.**

- Map ` + "`" + `sf::RenderWindow` + "`" + ` to ` + "`" + `ebiten.Game` + "`" + ` interface implementation from ` + "`" + `github.com/hajimehoshi/ebiten/v2` + "`" + ` or SDL2 window via ` + "`" + `go-sdl2` + "`" + `.
- Convert ` + "`" + `window.isOpen()` + "`" + ` main loop to Ebitengine's ` + "`" + `ebiten.RunGame(&game)` + "`" + ` or SDL2 event loop pattern.
- Replace ` + "`" + `sf::Texture` + "`" + ` / ` + "`" + `sf::Sprite` + "`" + ` with ` + "`" + `ebiten.NewImageFromImage(img)` + "`" + ` and ` + "`" + `ebiten.DrawImageOptions` + "`" + ` for drawing.
- Map ` + "`" + `window.pollEvent(event)` + "`" + ` to Ebitengine's ` + "`" + `Update()` + "`" + ` method with ` + "`" + `ebiten.IsKeyPressed` + "`" + ` or SDL2 ` + "`" + `sdl.PollEvent()` + "`" + `.
- Convert ` + "`" + `sf::Keyboard::isKeyPressed(sf::Keyboard::Left)` + "`" + ` to ` + "`" + `ebiten.IsKeyPressed(ebiten.KeyLeft)` + "`" + `.
- Replace ` + "`" + `sf::Clock` + "`" + ` / ` + "`" + `sf::Time` + "`" + ` with ` + "`" + `time.Now()` + "`" + ` and ` + "`" + `time.Since(start)` + "`" + ` for delta time.
- Map ` + "`" + `sf::SoundBuffer` + "`" + ` / ` + "`" + `sf::Sound` + "`" + ` to ` + "`" + `github.com/hajimehoshi/ebiten/v2/audio` + "`" + ` or SDL2 mixer.
- Convert ` + "`" + `sf::Font` + "`" + ` / ` + "`" + `sf::Text` + "`" + ` rendering to Ebitengine's ` + "`" + `text.Draw` + "`" + ` from ` + "`" + `github.com/hajimehoshi/ebiten/v2/text` + "`" + `.
- Replace ` + "`" + `sf::RectangleShape` + "`" + ` / ` + "`" + `sf::CircleShape` + "`" + ` with Ebitengine vector graphics via ` + "`" + `vector.DrawFilledRect` + "`" + ` or ` + "`" + `vector.DrawFilledCircle` + "`" + `.
- Map ` + "`" + `sf::View` + "`" + ` camera to custom transform matrices applied via ` + "`" + `ebiten.DrawImageOptions.GeoM` + "`" + `.
- Convert ` + "`" + `sf::TcpSocket` + "`" + ` / ` + "`" + `sf::UdpSocket` + "`" + ` to Go ` + "`" + `net.Dial("tcp", addr)` + "`" + ` / ` + "`" + `net.ListenPacket("udp", addr)` + "`" + `.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/cpp/spdlog.md",
			Body: `## spdlog to Go Conversion Rules

- Map ` + "`" + `#include <spdlog/spdlog.h>` + "`" + ` to ` + "`" + `import "log/slog"` + "`" + `.
- Convert ` + "`" + `spdlog::info("message {}", val)` + "`" + ` to ` + "`" + `slog.Info("message", "key", val)` + "`" + ` with structured key-value pairs.
- Replace ` + "`" + `spdlog::debug(...)` + "`" + ` with ` + "`" + `slog.Debug("message", "key", val)` + "`" + `.
- Map ` + "`" + `spdlog::warn(...)` + "`" + ` to ` + "`" + `slog.Warn("message", "key", val)` + "`" + `.
- Convert ` + "`" + `spdlog::error(...)` + "`" + ` to ` + "`" + `slog.Error("message", "key", val)` + "`" + `.
- Replace ` + "`" + `spdlog::critical(...)` + "`" + ` with ` + "`" + `slog.Error("message", "severity", "CRITICAL", "key", val)` + "`" + ` (Go has no critical level).
- Map ` + "`" + `spdlog::set_level(spdlog::level::debug)` + "`" + ` to ` + "`" + `slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))` + "`" + `.
- Convert ` + "`" + `spdlog::set_pattern("[%Y-%m-%d %H:%M:%S] [%l] %v")` + "`" + ` to custom ` + "`" + `slog.Handler` + "`" + ` with ` + "`" + `ReplaceAttr` + "`" + ` in ` + "`" + `HandlerOptions` + "`" + `.
- Replace ` + "`" + `spdlog::basic_logger_mt("name", "file.log")` + "`" + ` with ` + "`" + `slog.New(slog.NewJSONHandler(file, nil))` + "`" + ` where ` + "`" + `file` + "`" + ` is from ` + "`" + `os.OpenFile` + "`" + `.
- Map ` + "`" + `spdlog::rotating_logger_mt` + "`" + ` to ` + "`" + `slog.New(handler)` + "`" + ` with ` + "`" + `lumberjack.Logger` + "`" + ` as the ` + "`" + `io.Writer` + "`" + ` for log rotation.
- Convert ` + "`" + `spdlog::stdout_color_mt("console")` + "`" + ` to ` + "`" + `slog.New(slog.NewTextHandler(os.Stdout, nil))` + "`" + `.
- Replace named loggers ` + "`" + `spdlog::get("name")` + "`" + ` with distinct ` + "`" + `slog.Logger` + "`" + ` instances stored in a map or struct fields.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/cpp/sqlite.md",
			Body: `## SQLite C API to Go Conversion Rules

- Map ` + "`" + `#include <sqlite3.h>` + "`" + ` to ` + "`" + `import "database/sql"` + "`" + ` with ` + "`" + `_ "github.com/mattn/go-sqlite3"` + "`" + ` or ` + "`" + `_ "modernc.org/sqlite"` + "`" + ` (pure Go, no CGo).
- Convert ` + "`" + `sqlite3_open("file.db", &db)` + "`" + ` to ` + "`" + `db, err := sql.Open("sqlite3", "file.db")` + "`" + ` with defer ` + "`" + `db.Close()` + "`" + `.
- Replace ` + "`" + `sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)` + "`" + ` + ` + "`" + `sqlite3_bind_*` + "`" + ` with ` + "`" + `db.Prepare(query)` + "`" + ` and ` + "`" + `stmt.Exec(args...)` + "`" + ` or ` + "`" + `stmt.Query(args...)` + "`" + `.
- Map ` + "`" + `sqlite3_step(stmt)` + "`" + ` + ` + "`" + `sqlite3_column_*` + "`" + ` row iteration to ` + "`" + `rows, _ := db.Query(query); for rows.Next() { rows.Scan(&col1, &col2) }` + "`" + `.
- Convert ` + "`" + `sqlite3_exec(db, sql, callback, 0, &err)` + "`" + ` to ` + "`" + `db.Exec(sql)` + "`" + ` for statements or ` + "`" + `db.Query(sql)` + "`" + ` for results.
- Replace ` + "`" + `sqlite3_finalize(stmt)` + "`" + ` with ` + "`" + `stmt.Close()` + "`" + ` (or defer it).
- Map ` + "`" + `sqlite3_errmsg(db)` + "`" + ` to checking ` + "`" + `err` + "`" + ` return values from all ` + "`" + `database/sql` + "`" + ` methods.
- Convert ` + "`" + `sqlite3_transaction` + "`" + ` begin/commit/rollback to ` + "`" + `tx, _ := db.Begin()` + "`" + ` + ` + "`" + `tx.Commit()` + "`" + ` or ` + "`" + `tx.Rollback()` + "`" + `.
- Replace ` + "`" + `sqlite3_bind_text(stmt, idx, val, -1, SQLITE_TRANSIENT)` + "`" + ` with positional ` + "`" + `?` + "`" + ` placeholders in queries and passing args to ` + "`" + `Exec` + "`" + `/` + "`" + `Query` + "`" + `.
- Map ` + "`" + `sqlite3_last_insert_rowid(db)` + "`" + ` to ` + "`" + `result.LastInsertId()` + "`" + ` from ` + "`" + `sql.Result` + "`" + `.
- Convert ` + "`" + `sqlite3_changes(db)` + "`" + ` to ` + "`" + `result.RowsAffected()` + "`" + `.
- Replace manual memory management (` + "`" + `sqlite3_free` + "`" + `, ` + "`" + `sqlite3_malloc` + "`" + `) with Go's garbage collector (no manual cleanup needed).
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/cpp/stl.md",
			Body: `## STL to Go Conversion Rules

- Map ` + "`" + `std::vector<T>` + "`" + ` to Go slices ` + "`" + `[]T` + "`" + ` with ` + "`" + `append()` + "`" + ` for dynamic growth.
- Convert ` + "`" + `std::map<K,V>` + "`" + ` and ` + "`" + `std::unordered_map<K,V>` + "`" + ` to Go ` + "`" + `map[K]V` + "`" + `.
- Replace ` + "`" + `std::set<T>` + "`" + ` and ` + "`" + `std::unordered_set<T>` + "`" + ` with ` + "`" + `map[T]struct{}` + "`" + ` or ` + "`" + `map[T]bool` + "`" + `.
- Map ` + "`" + `std::sort(begin, end)` + "`" + ` to ` + "`" + `sort.Slice(s, func(i, j int) bool { ... })` + "`" + `.
- Convert ` + "`" + `std::find(begin, end, val)` + "`" + ` to a manual ` + "`" + `for range` + "`" + ` loop over the slice.
- Replace ` + "`" + `std::pair<A,B>` + "`" + ` with a named Go struct containing both fields.
- Map ` + "`" + `std::optional<T>` + "`" + ` to a pointer type ` + "`" + `*T` + "`" + ` where ` + "`" + `nil` + "`" + ` represents empty.
- Convert ` + "`" + `std::string` + "`" + ` to Go ` + "`" + `string` + "`" + ` (immutable) or ` + "`" + `strings.Builder` + "`" + ` for mutation.
- Replace ` + "`" + `std::unique_ptr<T>` + "`" + ` and ` + "`" + `std::shared_ptr<T>` + "`" + ` with plain Go values or pointers ` + "`" + `*T` + "`" + ` (GC handles lifetime).
- Map ` + "`" + `std::array<T,N>` + "`" + ` to Go fixed-size arrays ` + "`" + `[N]T` + "`" + `.
- Convert ` + "`" + `std::queue<T>` + "`" + ` and ` + "`" + `std::stack<T>` + "`" + ` to Go slices with append/pop idioms or ` + "`" + `container/list` + "`" + `.
- Replace ` + "`" + `std::tuple<A,B,C>` + "`" + ` with a named struct or multiple return values.
- Map ` + "`" + `std::for_each(begin, end, fn)` + "`" + ` to a ` + "`" + `for _, v := range slice { fn(v) }` + "`" + ` loop.
- Convert iterator patterns (` + "`" + `begin()` + "`" + `, ` + "`" + `end()` + "`" + `, ` + "`" + `++it` + "`" + `) to ` + "`" + `for i, v := range` + "`" + ` loops.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/cpp/tbb.md",
			Body: `## Intel TBB to Go Conversion Rules

- Map ` + "`" + `tbb::parallel_for(range, body)` + "`" + ` to a goroutine-per-chunk pattern with ` + "`" + `sync.WaitGroup` + "`" + ` for synchronization.
- Convert ` + "`" + `tbb::parallel_reduce(range, identity, body, join)` + "`" + ` to partitioned goroutines writing partial results to a channel, then reducing in the main goroutine.
- Replace ` + "`" + `tbb::concurrent_hash_map<K,V>` + "`" + ` with ` + "`" + `sync.Map` + "`" + ` or a ` + "`" + `map[K]V` + "`" + ` protected by ` + "`" + `sync.RWMutex` + "`" + `.
- Map ` + "`" + `tbb::concurrent_queue<T>` + "`" + ` to a buffered Go channel ` + "`" + `make(chan T, capacity)` + "`" + `.
- Convert ` + "`" + `tbb::concurrent_vector<T>` + "`" + ` to a slice protected by ` + "`" + `sync.Mutex` + "`" + `, or use append with mutex guards.
- Replace ` + "`" + `tbb::task_group` + "`" + ` with goroutines coordinated by ` + "`" + `sync.WaitGroup` + "`" + ` or ` + "`" + `errgroup.Group` + "`" + ` from ` + "`" + `golang.org/x/sync/errgroup` + "`" + `.
- Map ` + "`" + `tbb::flow::graph` + "`" + ` dataflow nodes to goroutines connected by typed channels forming a pipeline.
- Convert ` + "`" + `tbb::spin_mutex` + "`" + ` to ` + "`" + `sync.Mutex` + "`" + ` (Go's mutex is already lightweight).
- Replace ` + "`" + `tbb::parallel_pipeline` + "`" + ` with a staged goroutine pipeline: each stage reads from an input channel and writes to an output channel.
- Map ` + "`" + `tbb::blocked_range(0, n)` + "`" + ` partitioning to manual chunk calculation: ` + "`" + `chunkSize := n / numWorkers` + "`" + `.
- Convert ` + "`" + `tbb::global_control(max_allowed_parallelism, n)` + "`" + ` to ` + "`" + `runtime.GOMAXPROCS(n)` + "`" + `.
- Replace ` + "`" + `tbb::parallel_sort(begin, end)` + "`" + ` with ` + "`" + `sort.Slice` + "`" + ` (already efficient) or a parallel merge sort using goroutines for large datasets.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/cpp/vulkan.md",
			Body: `## Vulkan to Go Conversion Rules

**Warning: Go Vulkan bindings are experimental and less mature than C++ Vulkan. Consider whether the rendering requirements justify the porting effort.**

- Map ` + "`" + `#include <vulkan/vulkan.h>` + "`" + ` to ` + "`" + `import vk "github.com/vulkan-go/vulkan"` + "`" + ` with ` + "`" + `vk.Init()` + "`" + ` at startup.
- Convert ` + "`" + `vkCreateInstance(&createInfo, nullptr, &instance)` + "`" + ` to ` + "`" + `vk.CreateInstance(&instanceInfo, nil, &instance)` + "`" + ` with ` + "`" + `vk.Error(ret)` + "`" + ` checks.
- Replace ` + "`" + `vkCreateDevice(physDev, &devInfo, nullptr, &device)` + "`" + ` with ` + "`" + `vk.CreateDevice(physDev, &devInfo, nil, &device)` + "`" + `.
- Map ` + "`" + `vkEnumeratePhysicalDevices(instance, &count, devices)` + "`" + ` to ` + "`" + `vk.EnumeratePhysicalDevices(instance, &count, devices)` + "`" + `.
- Convert ` + "`" + `VkApplicationInfo` + "`" + ` struct initialization to ` + "`" + `vk.ApplicationInfo{ SType: vk.StructureTypeApplicationInfo, ... }` + "`" + `.
- Replace GLFW window surface creation with ` + "`" + `github.com/go-gl/glfw/v3.3/glfw` + "`" + ` and ` + "`" + `vk.CreateWindowSurface` + "`" + `.
- Map ` + "`" + `vkCreateSwapchainKHR` + "`" + ` to ` + "`" + `vk.CreateSwapchain(device, &swapchainInfo, nil, &swapchain)` + "`" + `.
- Convert ` + "`" + `vkAllocateCommandBuffers` + "`" + ` to ` + "`" + `vk.AllocateCommandBuffers(device, &allocInfo, cmdBuffers)` + "`" + `.
- Replace ` + "`" + `vkQueueSubmit` + "`" + ` / ` + "`" + `vkQueuePresentKHR` + "`" + ` with their ` + "`" + `vk.QueueSubmit` + "`" + ` / ` + "`" + `vk.QueuePresent` + "`" + ` equivalents.
- Map ` + "`" + `vkDestroyInstance(instance, nullptr)` + "`" + ` to ` + "`" + `vk.DestroyInstance(instance, nil)` + "`" + ` in deferred cleanup.
- Convert Vulkan validation layers setup to ` + "`" + `vk.InstanceCreateInfo` + "`" + ` with ` + "`" + `EnabledLayerNames` + "`" + ` slice.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/cpp/win32.md",
			Body: `## Win32 API to Go Conversion Rules

### windows.h — File Operations
- Convert ` + "`" + `CreateFile(path, access, share, NULL, disposition, flags, NULL)` + "`" + ` to ` + "`" + `os.OpenFile(path, flags, perm)` + "`" + `.
- Map ` + "`" + `ReadFile(handle, buf, count, &bytesRead, NULL)` + "`" + ` to ` + "`" + `file.Read(buf)` + "`" + `.
- Convert ` + "`" + `WriteFile(handle, buf, count, &bytesWritten, NULL)` + "`" + ` to ` + "`" + `file.Write(buf)` + "`" + `.
- Map ` + "`" + `CloseHandle(handle)` + "`" + ` to ` + "`" + `file.Close()` + "`" + ` — use with ` + "`" + `defer` + "`" + `.
- Convert ` + "`" + `GetFileSize(handle, NULL)` + "`" + ` to ` + "`" + `file.Stat()` + "`" + ` then ` + "`" + `info.Size()` + "`" + `.
- Map ` + "`" + `SetFilePointer(handle, offset, NULL, method)` + "`" + ` to ` + "`" + `file.Seek(offset, whence)` + "`" + `.
- Convert ` + "`" + `DeleteFile(path)` + "`" + ` to ` + "`" + `os.Remove(path)` + "`" + `.
- Map ` + "`" + `CreateDirectory(path, NULL)` + "`" + ` to ` + "`" + `os.Mkdir(path, 0o755)` + "`" + `.
- Convert ` + "`" + `RemoveDirectory(path)` + "`" + ` to ` + "`" + `os.Remove(path)` + "`" + `.
- Map ` + "`" + `MoveFile(src, dst)` + "`" + ` to ` + "`" + `os.Rename(src, dst)` + "`" + `.
- Convert ` + "`" + `CopyFile(src, dst, fail)` + "`" + ` — use ` + "`" + `io.Copy` + "`" + ` with ` + "`" + `os.Open` + "`" + `/` + "`" + `os.Create` + "`" + `.
- Map ` + "`" + `GetTempPath` + "`" + ` + ` + "`" + `GetTempFileName` + "`" + ` to ` + "`" + `os.CreateTemp(dir, pattern)` + "`" + `.

### windows.h — Threading
- Convert ` + "`" + `CreateThread(NULL, 0, func, arg, 0, NULL)` + "`" + ` to ` + "`" + `go func(arg)` + "`" + `.
- Map ` + "`" + `WaitForSingleObject(handle, INFINITE)` + "`" + ` to channel receive ` + "`" + `<-done` + "`" + ` or ` + "`" + `sync.WaitGroup.Wait()` + "`" + `.
- Convert ` + "`" + `WaitForMultipleObjects(count, handles, waitAll, timeout)` + "`" + ` to ` + "`" + `select` + "`" + ` on channels.
- Map ` + "`" + `CreateMutex/WaitForSingleObject/ReleaseMutex` + "`" + ` to ` + "`" + `sync.Mutex.Lock()/Unlock()` + "`" + `.
- Convert ` + "`" + `InitializeCriticalSection/EnterCriticalSection/LeaveCriticalSection` + "`" + ` to ` + "`" + `sync.Mutex` + "`" + `.
- Map ` + "`" + `CreateEvent/SetEvent/ResetEvent/WaitForSingleObject` + "`" + ` to channels.
- Convert ` + "`" + `Sleep(milliseconds)` + "`" + ` to ` + "`" + `time.Sleep(time.Duration(milliseconds) * time.Millisecond)` + "`" + `.
- Map ` + "`" + `InterlockedIncrement/InterlockedDecrement` + "`" + ` to ` + "`" + `atomic.AddInt32/AddInt64` + "`" + `.

### windows.h — Error Handling
- Convert ` + "`" + `GetLastError()` + "`" + ` to checking Go error returns.
- Map ` + "`" + `FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, ...)` + "`" + ` to ` + "`" + `err.Error()` + "`" + ` or ` + "`" + `syscall.Errno.Error()` + "`" + `.
- Convert error code checks to ` + "`" + `if err != nil { return err }` + "`" + `.

### windows.h — Memory
- Convert ` + "`" + `HeapAlloc/HeapFree` + "`" + ` to Go allocations with GC.
- Map ` + "`" + `VirtualAlloc/VirtualFree` + "`" + ` to ` + "`" + `syscall.VirtualAlloc/VirtualFree` + "`" + ` or ` + "`" + `golang.org/x/sys/windows` + "`" + `.
- Convert ` + "`" + `GlobalAlloc/GlobalFree` + "`" + ` to Go allocations.

### windows.h — Process
- Convert ` + "`" + `CreateProcess(...)` + "`" + ` to ` + "`" + `exec.Command(path, args...).Start()` + "`" + `.
- Map ` + "`" + `GetCurrentProcessId()` + "`" + ` to ` + "`" + `os.Getpid()` + "`" + `.
- Convert ` + "`" + `ExitProcess(code)` + "`" + ` to ` + "`" + `os.Exit(code)` + "`" + `.
- Map ` + "`" + `GetEnvironmentVariable(name, buf, size)` + "`" + ` to ` + "`" + `os.Getenv(name)` + "`" + `.
- Convert ` + "`" + `SetEnvironmentVariable(name, value)` + "`" + ` to ` + "`" + `os.Setenv(name, value)` + "`" + `.

### windows.h — Registry (platform-specific)
- Convert ` + "`" + `RegOpenKeyEx/RegQueryValueEx/RegCloseKey` + "`" + ` to ` + "`" + `golang.org/x/sys/windows/registry` + "`" + ` package.
- Note: Registry operations are Windows-only and should be behind build tags.

### winsock2.h + ws2tcpip.h — Networking
- Remove ` + "`" + `WSAStartup(MAKEWORD(2,2), &wsaData)` + "`" + ` / ` + "`" + `WSACleanup()` + "`" + ` — not needed in Go.
- Convert ` + "`" + `socket(AF_INET, SOCK_STREAM, 0)` + "`" + ` + ` + "`" + `connect` + "`" + ` to ` + "`" + `net.Dial("tcp", addr)` + "`" + `.
- Map ` + "`" + `socket` + "`" + ` + ` + "`" + `bind` + "`" + ` + ` + "`" + `listen` + "`" + ` + ` + "`" + `accept` + "`" + ` to ` + "`" + `net.Listen("tcp", addr)` + "`" + ` + ` + "`" + `listener.Accept()` + "`" + `.
- Convert ` + "`" + `send(sock, buf, len, 0)` + "`" + ` to ` + "`" + `conn.Write(buf)` + "`" + `.
- Map ` + "`" + `recv(sock, buf, len, 0)` + "`" + ` to ` + "`" + `conn.Read(buf)` + "`" + `.
- Convert ` + "`" + `closesocket(sock)` + "`" + ` to ` + "`" + `conn.Close()` + "`" + `.
- Map ` + "`" + `getaddrinfo(host, port, &hints, &result)` + "`" + ` to ` + "`" + `net.LookupHost(host)` + "`" + ` or ` + "`" + `net.ResolveTCPAddr` + "`" + `.
- Convert ` + "`" + `setsockopt` + "`" + ` to ` + "`" + `net.Dialer` + "`" + ` options or ` + "`" + `syscall.SetsockoptInt` + "`" + `.

### General Windows Patterns
- Use ` + "`" + `golang.org/x/sys/windows` + "`" + ` for direct Windows syscalls when no Go stdlib equivalent exists.
- Wrap Windows-specific code in files with ` + "`" + `_windows.go` + "`" + ` suffix and ` + "`" + `//go:build windows` + "`" + ` directive.
- Convert ` + "`" + `TCHAR` + "`" + `/` + "`" + `LPTSTR` + "`" + ` to Go ` + "`" + `string` + "`" + ` (use ` + "`" + `syscall.UTF16PtrFromString` + "`" + ` when calling Windows APIs via cgo/syscall).
- Map ` + "`" + `HANDLE` + "`" + ` to ` + "`" + `syscall.Handle` + "`" + ` or ` + "`" + `windows.Handle` + "`" + `.
- Convert ` + "`" + `BOOL` + "`" + `/` + "`" + `TRUE` + "`" + `/` + "`" + `FALSE` + "`" + ` to Go ` + "`" + `bool` + "`" + `/` + "`" + `true` + "`" + `/` + "`" + `false` + "`" + `.
- Map ` + "`" + `DWORD` + "`" + ` to ` + "`" + `uint32` + "`" + `, ` + "`" + `WORD` + "`" + ` to ` + "`" + `uint16` + "`" + `, ` + "`" + `BYTE` + "`" + ` to ` + "`" + `byte` + "`" + `.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/cpp/wxwidgets.md",
			Body: `## wxWidgets to Go Conversion Rules

**Warning: Go GUI libraries (fyne, gio) have significantly fewer widgets than wxWidgets. Complex wxWidgets applications may require substantial redesign or alternative approaches.**

- Map ` + "`" + `wxApp` + "`" + ` / ` + "`" + `wxFrame` + "`" + ` application structure to ` + "`" + `app := app.New(); w := app.NewWindow("title")` + "`" + ` from ` + "`" + `fyne.io/fyne/v2` + "`" + `.
- Convert ` + "`" + `wxButton(parent, id, "label")` + "`" + ` to ` + "`" + `widget.NewButton("label", func() { ... })` + "`" + ` in fyne.
- Replace ` + "`" + `wxStaticText(parent, id, "text")` + "`" + ` with ` + "`" + `widget.NewLabel("text")` + "`" + `.
- Map ` + "`" + `wxTextCtrl` + "`" + ` to ` + "`" + `widget.NewEntry()` + "`" + ` for single-line or ` + "`" + `widget.NewMultiLineEntry()` + "`" + ` for multi-line input.
- Convert ` + "`" + `wxBoxSizer(wxVERTICAL)` + "`" + ` / ` + "`" + `wxBoxSizer(wxHORIZONTAL)` + "`" + ` to ` + "`" + `container.NewVBox(...)` + "`" + ` / ` + "`" + `container.NewHBox(...)` + "`" + `.
- Replace ` + "`" + `Bind(wxEVT_BUTTON, &handler)` + "`" + ` event binding with callback functions passed to widget constructors.
- Map ` + "`" + `wxMenuBar` + "`" + ` / ` + "`" + `wxMenu` + "`" + ` to ` + "`" + `fyne.NewMainMenu(fyne.NewMenu("File", ...))` + "`" + `.
- Convert ` + "`" + `wxFileDialog` + "`" + ` to ` + "`" + `dialog.ShowFileOpen(callback, window)` + "`" + ` in fyne.
- Replace ` + "`" + `wxMessageBox("msg", "title")` + "`" + ` with ` + "`" + `dialog.ShowInformation("title", "msg", window)` + "`" + `.
- Map ` + "`" + `wxListCtrl` + "`" + ` / ` + "`" + `wxTreeCtrl` + "`" + ` to ` + "`" + `widget.NewList(...)` + "`" + ` / ` + "`" + `widget.NewTree(...)` + "`" + ` in fyne.
- Convert ` + "`" + `wxTimer` + "`" + ` to ` + "`" + `time.NewTicker` + "`" + ` or ` + "`" + `time.AfterFunc` + "`" + ` with goroutine coordination.
- Replace ` + "`" + `wxThread` + "`" + ` / ` + "`" + `wxMutex` + "`" + ` with goroutines and ` + "`" + `sync.Mutex` + "`" + `.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/cpp/zmq.md",
			Body: `## ZeroMQ to Go Conversion Rules

- Map ` + "`" + `#include <zmq.hpp>` + "`" + ` to ` + "`" + `import zmq "github.com/pebbe/zmq4"` + "`" + ` (cgo) or ` + "`" + `import "github.com/go-zeromq/zmq4"` + "`" + ` (pure Go).
- Convert ` + "`" + `zmq::context_t ctx(1)` + "`" + ` to ` + "`" + `ctx, _ := zmq.NewContext()` + "`" + ` or use the default context.
- Replace ` + "`" + `zmq::socket_t socket(ctx, zmq::socket_type::req)` + "`" + ` with ` + "`" + `socket, _ := zmq.NewREQ(ctx)` + "`" + ` (pure Go) or ` + "`" + `socket, _ := ctx.NewSocket(zmq.REQ)` + "`" + ` (cgo).
- Map ` + "`" + `socket.bind("tcp://*:5555")` + "`" + ` to ` + "`" + `socket.Listen("tcp://*:5555")` + "`" + ` (pure Go) or ` + "`" + `socket.Bind("tcp://*:5555")` + "`" + ` (cgo).
- Convert ` + "`" + `socket.connect("tcp://host:5555")` + "`" + ` to ` + "`" + `socket.Dial("tcp://host:5555")` + "`" + ` (pure Go) or ` + "`" + `socket.Connect(...)` + "`" + ` (cgo).
- Replace ` + "`" + `socket.send(zmq::buffer(data), flags)` + "`" + ` with ` + "`" + `socket.Send(zmq.NewMsgFrom(data))` + "`" + ` (pure Go) or ` + "`" + `socket.SendBytes(data, flags)` + "`" + ` (cgo).
- Map ` + "`" + `socket.recv(msg)` + "`" + ` to ` + "`" + `msg, _ := socket.Recv()` + "`" + ` (pure Go) or ` + "`" + `data, _ := socket.RecvBytes(0)` + "`" + ` (cgo).
- Convert ` + "`" + `ZMQ_PUB` + "`" + ` / ` + "`" + `ZMQ_SUB` + "`" + ` pub-sub pattern to ` + "`" + `zmq.NewPUB(ctx)` + "`" + ` / ` + "`" + `zmq.NewSUB(ctx)` + "`" + ` with ` + "`" + `sub.SetOption(zmq.OptionSubscribe, "topic")` + "`" + `.
- Replace ` + "`" + `ZMQ_PUSH` + "`" + ` / ` + "`" + `ZMQ_PULL` + "`" + ` pipeline pattern to ` + "`" + `zmq.NewPUSH(ctx)` + "`" + ` / ` + "`" + `zmq.NewPULL(ctx)` + "`" + `.
- Map ` + "`" + `zmq_poll` + "`" + ` multiplexing to ` + "`" + `zmq.NewReactor()` + "`" + ` or use goroutines with one socket per goroutine.
- Convert ` + "`" + `ZMQ_ROUTER` + "`" + ` / ` + "`" + `ZMQ_DEALER` + "`" + ` to their Go equivalents for async request-reply patterns.
- Replace ZMQ multipart messages (` + "`" + `zmq::send_flags::sndmore` + "`" + `) with ` + "`" + `zmq.NewMsgFrom(frames...)` + "`" + ` combining multiple frames.
`,
		},
	)
}
