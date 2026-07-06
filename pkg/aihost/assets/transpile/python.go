/*
Copyright (c) 2026 Security Research
*/
package transpile

import "github.com/inovacc/unravel-oss/pkg/aihost"

func init() {
	aihost.RegisterAsset(
		aihost.Asset{
			Path: "skills/transpile/rules/python/aiohttp.md",
			Body: `## aiohttp to Go Conversion Rules

- Replace ` + "`" + `aiohttp.ClientSession()` + "`" + ` with ` + "`" + `http.Client{}` + "`" + ` — Go's HTTP client is inherently concurrent.
- Map ` + "`" + `async with session.get(url) as resp:` + "`" + ` to ` + "`" + `resp, err := client.Get(url)` + "`" + ` + ` + "`" + `defer resp.Body.Close()` + "`" + `.
- Convert ` + "`" + `async with session.post(url, json=data) as resp:` + "`" + ` to ` + "`" + `http.Post(url, "application/json", body)` + "`" + `.
- Replace ` + "`" + `resp.json()` + "`" + ` with ` + "`" + `json.NewDecoder(resp.Body).Decode(&target)` + "`" + `.
- Map ` + "`" + `resp.text()` + "`" + ` to ` + "`" + `io.ReadAll(resp.Body)` + "`" + ` + ` + "`" + `string(body)` + "`" + `.
- Convert ` + "`" + `aiohttp.web.Application()` + "`" + ` to ` + "`" + `http.NewServeMux()` + "`" + ` or chi router.
- Replace ` + "`" + `app.router.add_get("/path", handler)` + "`" + ` with ` + "`" + `mux.HandleFunc("GET /path", handler)` + "`" + ` or ` + "`" + `r.Get("/path", handler)` + "`" + `.
- Map ` + "`" + `aiohttp.web.Request` + "`" + ` to ` + "`" + `*http.Request` + "`" + `.
- Convert ` + "`" + `aiohttp.web.Response(text=body)` + "`" + ` to ` + "`" + `w.Write([]byte(body))` + "`" + `.
- Replace ` + "`" + `aiohttp.web.json_response(data)` + "`" + ` with ` + "`" + `json.NewEncoder(w).Encode(data)` + "`" + ` + content-type header.
- Map ` + "`" + `aiohttp.web.WebSocketResponse()` + "`" + ` to ` + "`" + `nhooyr.io/websocket` + "`" + ` accept + read/write.
- Convert ` + "`" + `session.ws_connect(url)` + "`" + ` to ` + "`" + `websocket.Dial(ctx, url, nil)` + "`" + `.
- Replace ` + "`" + `aiohttp.TCPConnector(limit=N)` + "`" + ` with ` + "`" + `http.Transport{MaxConnsPerHost: N}` + "`" + `.
- Map ` + "`" + `aiohttp.ClientTimeout(total=N)` + "`" + ` to ` + "`" + `http.Client{Timeout: N * time.Second}` + "`" + `.
- Convert middleware ` + "`" + `@aiohttp.web.middleware` + "`" + ` to chi middleware functions or ` + "`" + `http.Handler` + "`" + ` wrappers.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/python/argparse.md",
			Body: `## argparse to Go Conversion Rules

- Replace ` + "`" + `argparse.ArgumentParser()` + "`" + ` with a ` + "`" + `cobra.Command` + "`" + ` struct or ` + "`" + `flag` + "`" + ` package.
- Map ` + "`" + `parser.add_argument("--name", type=str, default="")` + "`" + ` to ` + "`" + `flag.StringVar(&name, "name", "", "description")` + "`" + ` or ` + "`" + `cmd.Flags().StringVar(...)` + "`" + `.
- Convert ` + "`" + `parser.add_argument("filename")` + "`" + ` positional arguments to ` + "`" + `cobra.ExactArgs(N)` + "`" + ` with ` + "`" + `args[i]` + "`" + `.
- Replace ` + "`" + `parser.add_argument("--verbose", action="store_true")` + "`" + ` with ` + "`" + `flag.BoolVar(&verbose, "verbose", false, "description")` + "`" + `.
- Map ` + "`" + `parser.add_argument("--count", type=int, required=True)` + "`" + ` to a required flag with validation.
- Convert ` + "`" + `parser.add_argument(choices=["a", "b"])` + "`" + ` to manual validation after parsing.
- Replace ` + "`" + `args = parser.parse_args()` + "`" + ` with ` + "`" + `flag.Parse()` + "`" + ` or cobra's automatic parsing.
- Map ` + "`" + `parser.add_subparsers()` + "`" + ` to cobra subcommands via ` + "`" + `rootCmd.AddCommand(subCmd)` + "`" + `.
- Convert ` + "`" + `parser.add_argument(nargs="+")` + "`" + ` (multiple values) to ` + "`" + `flag.Args()` + "`" + ` or a string slice flag.
- Replace ` + "`" + `parser.add_mutually_exclusive_group()` + "`" + ` with manual validation in the command's ` + "`" + `RunE` + "`" + ` function.
- Map ` + "`" + `parser.error("message")` + "`" + ` to ` + "`" + `return fmt.Errorf("message")` + "`" + ` or ` + "`" + `cmd.Usage()` + "`" + ` + error return.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/python/asyncio.md",
			Body: `## asyncio to Go Conversion Rules

- Replace ` + "`" + `async def` + "`" + ` functions with regular Go functions; Go handles concurrency at the runtime level with goroutines.
- Map ` + "`" + `await coroutine()` + "`" + ` calls to direct function calls or channel receives depending on context.
- Convert ` + "`" + `asyncio.gather(*tasks)` + "`" + ` to ` + "`" + `errgroup.Group` + "`" + ` with goroutines for each task.
- Replace ` + "`" + `asyncio.create_task(coro)` + "`" + ` with ` + "`" + `go func() { ... }()` + "`" + ` goroutine launches.
- Map ` + "`" + `asyncio.Queue` + "`" + ` to buffered Go channels (` + "`" + `make(chan T, size)` + "`" + `).
- Convert ` + "`" + `asyncio.Semaphore(n)` + "`" + ` to ` + "`" + `make(chan struct{}, n)` + "`" + ` or ` + "`" + `golang.org/x/sync/semaphore` + "`" + `.
- Replace ` + "`" + `asyncio.Lock` + "`" + ` with ` + "`" + `sync.Mutex` + "`" + `.
- Map ` + "`" + `asyncio.Event` + "`" + ` to ` + "`" + `sync.Cond` + "`" + ` or a channel-based signal.
- Convert ` + "`" + `asyncio.wait_for(coro, timeout=N)` + "`" + ` to ` + "`" + `context.WithTimeout` + "`" + ` + ` + "`" + `select` + "`" + ` on ` + "`" + `ctx.Done()` + "`" + `.
- Replace ` + "`" + `asyncio.sleep(N)` + "`" + ` with ` + "`" + `time.Sleep(N * time.Second)` + "`" + ` or ` + "`" + `select` + "`" + ` with ` + "`" + `time.After` + "`" + `.
- Map ` + "`" + `async for item in async_iterator` + "`" + ` to a goroutine writing to a channel + ` + "`" + `for item := range ch` + "`" + `.
- Convert ` + "`" + `async with` + "`" + ` context managers to explicit resource acquisition + ` + "`" + `defer` + "`" + ` cleanup.
- Replace ` + "`" + `asyncio.run(main())` + "`" + ` with direct ` + "`" + `main()` + "`" + ` invocation (Go programs are concurrent by default).
- Map ` + "`" + `asyncio.shield(coro)` + "`" + ` to running in a separate goroutine with its own context.
- Convert ` + "`" + `asyncio.StreamReader` + "`" + ` / ` + "`" + `asyncio.StreamWriter` + "`" + ` to ` + "`" + `net.Conn` + "`" + ` with ` + "`" + `bufio.Reader` + "`" + ` / ` + "`" + `bufio.Writer` + "`" + `.
- Replace callback-based patterns (` + "`" + `add_done_callback` + "`" + `) with goroutines that send results on channels.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/python/boto3.md",
			Body: `## boto3 / botocore to Go Conversion Rules

- Replace ` + "`" + `boto3.client("service")` + "`" + ` with ` + "`" + `aws-sdk-go-v2` + "`" + ` service client constructors (e.g., ` + "`" + `s3.NewFromConfig(cfg)` + "`" + `).
- Map ` + "`" + `boto3.Session()` + "`" + ` to ` + "`" + `config.LoadDefaultConfig(ctx)` + "`" + ` from ` + "`" + `github.com/aws/aws-sdk-go-v2/config` + "`" + `.
- Convert S3 operations: ` + "`" + `put_object()` + "`" + ` → ` + "`" + `s3.PutObject()` + "`" + `, ` + "`" + `get_object()` + "`" + ` → ` + "`" + `s3.GetObject()` + "`" + `, ` + "`" + `list_objects_v2()` + "`" + ` → ` + "`" + `s3.ListObjectsV2()` + "`" + `.
- Replace ` + "`" + `s3.download_file()` + "`" + ` / ` + "`" + `s3.upload_file()` + "`" + ` with ` + "`" + `s3manager.Downloader` + "`" + ` / ` + "`" + `s3manager.Uploader` + "`" + `.
- Map DynamoDB operations: ` + "`" + `put_item()` + "`" + ` → ` + "`" + `dynamodb.PutItem()` + "`" + `, ` + "`" + `get_item()` + "`" + ` → ` + "`" + `dynamodb.GetItem()` + "`" + `, ` + "`" + `query()` + "`" + ` → ` + "`" + `dynamodb.Query()` + "`" + `.
- Convert DynamoDB ` + "`" + `Key` + "`" + ` / ` + "`" + `ExpressionAttributeValues` + "`" + ` dicts to ` + "`" + `types.AttributeValue` + "`" + ` structs using ` + "`" + `attributevalue.MarshalMap()` + "`" + `.
- Replace SQS operations: ` + "`" + `send_message()` + "`" + ` → ` + "`" + `sqs.SendMessage()` + "`" + `, ` + "`" + `receive_message()` + "`" + ` → ` + "`" + `sqs.ReceiveMessage()` + "`" + `, ` + "`" + `delete_message()` + "`" + ` → ` + "`" + `sqs.DeleteMessage()` + "`" + `.
- Map SNS ` + "`" + `publish()` + "`" + ` to ` + "`" + `sns.Publish()` + "`" + `.
- Convert Lambda ` + "`" + `invoke()` + "`" + ` to ` + "`" + `lambda.Invoke()` + "`" + `.
- Replace ` + "`" + `boto3.resource("s3")` + "`" + ` high-level API with explicit ` + "`" + `s3.Client` + "`" + ` method calls (Go SDK has no resource abstraction).
- Map paginator patterns (` + "`" + `client.get_paginator("list_objects_v2")` + "`" + `) to Go SDK paginators (e.g., ` + "`" + `s3.NewListObjectsV2Paginator(client, params)` + "`" + `).
- Convert waiter patterns (` + "`" + `client.get_waiter("instance_running").wait()` + "`" + `) to Go SDK waiters.
- Replace ` + "`" + `ClientError` + "`" + ` / ` + "`" + `botocore.exceptions` + "`" + ` with ` + "`" + `smithy.APIError` + "`" + ` and ` + "`" + `errors.As` + "`" + ` type assertions.
- Map ` + "`" + `aws_access_key_id` + "`" + ` / ` + "`" + `aws_secret_access_key` + "`" + ` to environment variables or AWS config file (Go SDK auto-loads from standard locations).
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/python/celery.md",
			Body: `## Celery to Go Conversion Rules

- Replace Celery ` + "`" + `@app.task` + "`" + ` decorated functions with plain Go functions invoked via goroutines and channels.
- For broker-based task queues, use ` + "`" + `github.com/hibiken/asynq` + "`" + ` (Redis-backed) or ` + "`" + `github.com/RichardKnop/machinery` + "`" + ` as the Go equivalent.
- Map ` + "`" + `delay()` + "`" + ` / ` + "`" + `apply_async()` + "`" + ` calls to goroutine launches or ` + "`" + `asynq.Client.Enqueue()` + "`" + `.
- Convert Celery task result backends to channel returns or ` + "`" + `asynq` + "`" + ` task results.
- Replace ` + "`" + `chord()` + "`" + `, ` + "`" + `group()` + "`" + `, ` + "`" + `chain()` + "`" + ` task primitives with ` + "`" + `sync.WaitGroup` + "`" + `, ` + "`" + `errgroup.Group` + "`" + `, or sequential goroutine orchestration.
- Map periodic tasks (` + "`" + `@periodic_task` + "`" + `, ` + "`" + `celery.beat` + "`" + `) to ` + "`" + `time.Ticker` + "`" + ` or a cron library like ` + "`" + `github.com/robfig/cron/v3` + "`" + `.
- Convert ` + "`" + `task.retry()` + "`" + ` to explicit retry loops with backoff using ` + "`" + `time.Sleep` + "`" + ` or ` + "`" + `github.com/cenkalti/backoff` + "`" + `.
- Replace Celery signals (` + "`" + `task_prerun` + "`" + `, ` + "`" + `task_postrun` + "`" + `, ` + "`" + `task_failure` + "`" + `) with middleware wrapper functions or defer-based hooks.
- Map ` + "`" + `celery.canvas` + "`" + ` (workflows) to explicit Go pipeline patterns using channels.
- Convert ` + "`" + `rate_limit` + "`" + ` task options to ` + "`" + `golang.org/x/time/rate` + "`" + ` limiters.
- Replace ` + "`" + `SoftTimeLimitExceeded` + "`" + ` / ` + "`" + `TimeLimitExceeded` + "`" + ` with ` + "`" + `context.WithTimeout` + "`" + ` and ` + "`" + `ctx.Done()` + "`" + ` checks.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/python/click.md",
			Body: `## click to Go Conversion Rules

- Replace ` + "`" + `@click.command()` + "`" + ` with a ` + "`" + `cobra.Command` + "`" + ` struct.
- Map ` + "`" + `@click.group()` + "`" + ` with subcommands to a root ` + "`" + `cobra.Command` + "`" + ` with ` + "`" + `AddCommand()` + "`" + ` children.
- Convert ` + "`" + `@click.option("--name", type=str, default="")` + "`" + ` to ` + "`" + `cmd.Flags().StringVarP(&name, "name", "", "", "description")` + "`" + `.
- Replace ` + "`" + `@click.option("--count", type=int)` + "`" + ` with ` + "`" + `cmd.Flags().IntVar(&count, "count", 0, "description")` + "`" + `.
- Map ` + "`" + `@click.option("--verbose", is_flag=True)` + "`" + ` to ` + "`" + `cmd.Flags().BoolVar(&verbose, "verbose", false, "description")` + "`" + `.
- Convert ` + "`" + `@click.argument("filename")` + "`" + ` to ` + "`" + `cobra.ExactArgs(1)` + "`" + ` with ` + "`" + `args[0]` + "`" + ` in the run function.
- Replace ` + "`" + `@click.option(required=True)` + "`" + ` with ` + "`" + `cmd.MarkFlagRequired("name")` + "`" + `.
- Map ` + "`" + `@click.option(type=click.Choice(["a", "b"]))` + "`" + ` to a custom flag with validation or ` + "`" + `cobra.RegisterFlagCompletionFunc` + "`" + `.
- Convert ` + "`" + `click.echo()` + "`" + ` to ` + "`" + `fmt.Println()` + "`" + ` or ` + "`" + `fmt.Fprintf(os.Stdout, ...)` + "`" + `.
- Replace ` + "`" + `click.secho(msg, fg="green")` + "`" + ` with ` + "`" + `fmt.Println(msg)` + "`" + ` or a color library like ` + "`" + `github.com/fatih/color` + "`" + `.
- Map ` + "`" + `click.confirm("Continue?")` + "`" + ` to ` + "`" + `bufio.NewReader(os.Stdin).ReadString('\n')` + "`" + ` with prompt.
- Convert ` + "`" + `click.File()` + "`" + ` parameters to ` + "`" + `os.Open()` + "`" + ` / ` + "`" + `os.Create()` + "`" + ` in the command body.
- Replace ` + "`" + `@click.pass_context` + "`" + ` with explicit parameter passing or a config struct.
- Map ` + "`" + `click.testing.CliRunner` + "`" + ` to ` + "`" + `cmd.Execute()` + "`" + ` with captured stdout in tests.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/python/collections.md",
			Body: `## collections to Go Conversion Rules

- Replace ` + "`" + `collections.defaultdict(list)` + "`" + ` with a ` + "`" + `map[K][]V` + "`" + ` and check-before-append pattern.
- Map ` + "`" + `collections.defaultdict(int)` + "`" + ` to a plain ` + "`" + `map[K]int` + "`" + ` (zero value is already 0 in Go).
- Convert ` + "`" + `collections.defaultdict(set)` + "`" + ` to ` + "`" + `map[K]map[V]struct{}` + "`" + ` with lazy init.
- Replace ` + "`" + `collections.Counter(items)` + "`" + ` with a ` + "`" + `map[T]int` + "`" + ` populated via a counting loop.
- Map ` + "`" + `counter.most_common(n)` + "`" + ` to sorting the map entries by value and taking the top N.
- Convert ` + "`" + `collections.OrderedDict` + "`" + ` — Go maps do not preserve insertion order. Use a slice of key-value pairs or ` + "`" + `github.com/elliotchance/orderedmap/v2` + "`" + `.
- Replace ` + "`" + `collections.deque()` + "`" + ` with a slice (` + "`" + `append` + "`" + ` / slice-from-front) or ` + "`" + `container/list` + "`" + ` for O(1) operations on both ends.
- Map ` + "`" + `deque(maxlen=N)` + "`" + ` to a ring buffer using ` + "`" + `container/ring` + "`" + ` or a custom bounded slice.
- Convert ` + "`" + `collections.namedtuple("Name", ["field1", "field2"])` + "`" + ` to a Go struct with named fields.
- Replace ` + "`" + `collections.ChainMap` + "`" + ` with a lookup function that iterates over multiple maps.
- Map ` + "`" + `collections.abc.Iterable` + "`" + ` / ` + "`" + `Sequence` + "`" + ` / ` + "`" + `Mapping` + "`" + ` type hints to Go interfaces or concrete types.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/python/dataclasses.md",
			Body: `## dataclasses to Go Conversion Rules

- Replace ` + "`" + `@dataclass` + "`" + ` decorated classes with plain Go structs.
- Map dataclass fields with type annotations to Go struct fields with appropriate types.
- Convert ` + "`" + `field(default=value)` + "`" + ` to Go struct field with default set in a constructor function.
- Replace ` + "`" + `field(default_factory=list)` + "`" + ` with a constructor function that initializes the slice: ` + "`" + `func NewMyStruct() MyStruct { return MyStruct{Items: []string{}} }` + "`" + `.
- Map ` + "`" + `__post_init__` + "`" + ` to logic in the constructor function.
- Convert ` + "`" + `@dataclass(frozen=True)` + "`" + ` to a struct with unexported fields + getter methods (Go has no immutability enforcement; document the intent).
- Replace ` + "`" + `@dataclass(order=True)` + "`" + ` with implementing ` + "`" + `sort.Interface` + "`" + ` or a comparison function.
- Map ` + "`" + `asdict(instance)` + "`" + ` to a manual ` + "`" + `ToMap() map[string]any` + "`" + ` method or ` + "`" + `json.Marshal` + "`" + ` + ` + "`" + `json.Unmarshal` + "`" + ` roundtrip.
- Convert ` + "`" + `astuple(instance)` + "`" + ` to a method returning multiple values.
- Replace ` + "`" + `@dataclass(eq=True)` + "`" + ` — Go structs are comparable by default if all fields are comparable.
- Map ` + "`" + `field(repr=False)` + "`" + ` to a custom ` + "`" + `String() string` + "`" + ` method that excludes specific fields.
- Convert ` + "`" + `field(init=False)` + "`" + ` to setting the field after construction or in the constructor function.
- Replace ` + "`" + `__hash__` + "`" + ` with a custom hash method if the struct is used as a map key.
- Map ` + "`" + `dataclasses.replace(instance, field=value)` + "`" + ` to copying the struct and modifying the field.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/python/django.md",
			Body: `## Django to Go Conversion Rules

- Map Django URL patterns (` + "`" + `urlpatterns` + "`" + `, ` + "`" + `path()` + "`" + `, ` + "`" + `re_path()` + "`" + `) to chi router routes (` + "`" + `r.Get` + "`" + `, ` + "`" + `r.Post` + "`" + `, etc.).
- Convert Django views (function-based and class-based) to ` + "`" + `http.HandlerFunc` + "`" + ` or chi handler functions.
- Replace ` + "`" + `django.db.models.Model` + "`" + ` subclasses with Go structs + sqlc-generated query functions.
- Map Django ORM queries (` + "`" + `filter()` + "`" + `, ` + "`" + `exclude()` + "`" + `, ` + "`" + `get()` + "`" + `) to raw SQL via sqlc or ` + "`" + `database/sql` + "`" + `.
- Convert Django forms to Go structs with ` + "`" + `go-playground/validator` + "`" + ` tags.
- Replace ` + "`" + `django.conf.settings` + "`" + ` access with a config struct loaded from environment variables.
- Map Django middleware classes to chi middleware functions.
- Replace ` + "`" + `django.contrib.auth` + "`" + ` with custom auth middleware + bcrypt for password hashing.
- Convert Django template rendering (` + "`" + `render()` + "`" + `, ` + "`" + `TemplateResponse` + "`" + `) to ` + "`" + `html/template.Execute` + "`" + `.
- Map Django signals (` + "`" + `pre_save` + "`" + `, ` + "`" + `post_save` + "`" + `) to explicit function calls or event channels.
- Replace ` + "`" + `django.test.TestCase` + "`" + ` with Go ` + "`" + `testing` + "`" + ` package + ` + "`" + `testify` + "`" + ` assertions.
- Convert ` + "`" + `manage.py` + "`" + ` commands to cobra CLI subcommands.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/python/docker.md",
			Body: `## docker to Go Conversion Rules

- Replace ` + "`" + `import docker` + "`" + ` / ` + "`" + `docker.from_env()` + "`" + ` with ` + "`" + `client.NewClientWithOpts(client.FromEnv)` + "`" + ` from ` + "`" + `github.com/docker/docker/client` + "`" + `.
- Map ` + "`" + `client.containers.list()` + "`" + ` to ` + "`" + `cli.ContainerList(ctx, container.ListOptions{})` + "`" + `.
- Convert ` + "`" + `client.containers.run(image, command)` + "`" + ` to ` + "`" + `cli.ContainerCreate()` + "`" + ` + ` + "`" + `cli.ContainerStart()` + "`" + `.
- Replace ` + "`" + `container.stop()` + "`" + ` with ` + "`" + `cli.ContainerStop(ctx, containerID, container.StopOptions{})` + "`" + `.
- Map ` + "`" + `container.remove()` + "`" + ` to ` + "`" + `cli.ContainerRemove(ctx, containerID, container.RemoveOptions{})` + "`" + `.
- Convert ` + "`" + `container.logs()` + "`" + ` to ` + "`" + `cli.ContainerLogs(ctx, containerID, container.LogsOptions{ShowStdout: true})` + "`" + `.
- Replace ` + "`" + `container.exec_run(cmd)` + "`" + ` with ` + "`" + `cli.ContainerExecCreate()` + "`" + ` + ` + "`" + `cli.ContainerExecStart()` + "`" + `.
- Map ` + "`" + `client.images.pull(name)` + "`" + ` to ` + "`" + `cli.ImagePull(ctx, name, image.PullOptions{})` + "`" + `.
- Convert ` + "`" + `client.images.build(path=".")` + "`" + ` to ` + "`" + `cli.ImageBuild(ctx, tarContext, types.ImageBuildOptions{})` + "`" + `.
- Replace ` + "`" + `client.images.list()` + "`" + ` with ` + "`" + `cli.ImageList(ctx, image.ListOptions{})` + "`" + `.
- Map ` + "`" + `client.networks.create(name)` + "`" + ` to ` + "`" + `cli.NetworkCreate(ctx, name, network.CreateOptions{})` + "`" + `.
- Convert ` + "`" + `client.volumes.create(name)` + "`" + ` to ` + "`" + `cli.VolumeCreate(ctx, volume.CreateOptions{Name: name})` + "`" + `.
- Replace Docker Compose operations with ` + "`" + `github.com/docker/compose/v2` + "`" + ` Go API or shell-out to ` + "`" + `docker compose` + "`" + `.
- Map ` + "`" + `docker.errors.NotFound` + "`" + ` to checking error types with ` + "`" + `errdefs.IsNotFound(err)` + "`" + `.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/python/fastapi.md",
			Body: `## FastAPI to Go Conversion Rules

- Map FastAPI ` + "`" + `@app.get` + "`" + `, ` + "`" + `@app.post` + "`" + `, etc. decorators to chi/fiber/echo route registrations.
- Convert ` + "`" + `APIRouter` + "`" + ` to chi ` + "`" + `r.Route` + "`" + ` or ` + "`" + `r.Group` + "`" + ` sub-routers.
- Replace Pydantic request/response models with Go structs + JSON struct tags.
- Map FastAPI ` + "`" + `Depends()` + "`" + ` dependency injection to middleware or explicit function parameters.
- Convert path parameters (` + "`" + `{item_id: int}` + "`" + `) to chi URL params (` + "`" + `chi.URLParam(r, "item_id")` + "`" + `) with manual type parsing.
- Replace ` + "`" + `Query()` + "`" + `, ` + "`" + `Body()` + "`" + `, ` + "`" + `Header()` + "`" + ` parameter annotations with explicit ` + "`" + `r.URL.Query().Get()` + "`" + `, ` + "`" + `json.NewDecoder(r.Body)` + "`" + `, ` + "`" + `r.Header.Get()` + "`" + `.
- Map FastAPI ` + "`" + `HTTPException(status_code=N, detail=msg)` + "`" + ` to ` + "`" + `http.Error(w, msg, N)` + "`" + `.
- Convert FastAPI background tasks (` + "`" + `BackgroundTasks` + "`" + `) to goroutines.
- Replace ` + "`" + `@app.on_event("startup")` + "`" + ` / ` + "`" + `@app.on_event("shutdown")` + "`" + ` with ` + "`" + `http.Server` + "`" + ` lifecycle hooks or signal handling.
- Map FastAPI ` + "`" + `UploadFile` + "`" + ` to ` + "`" + `r.FormFile()` + "`" + ` + ` + "`" + `multipart.File` + "`" + `.
- Convert FastAPI WebSocket endpoints to ` + "`" + `nhooyr.io/websocket` + "`" + ` handlers.
- Replace ` + "`" + `response_model` + "`" + ` serialization with explicit ` + "`" + `json.NewEncoder(w).Encode()` + "`" + `.
- Map FastAPI automatic OpenAPI generation to manual swagger comments or ` + "`" + `swaggo/swag` + "`" + `.
- Convert ` + "`" + `async def` + "`" + ` endpoints to regular Go handler functions (Go handles concurrency at the runtime level).
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/python/flask.md",
			Body: `## Flask to Go Conversion Rules

- Map Flask ` + "`" + `@app.route` + "`" + ` decorators to chi router registrations (` + "`" + `r.Get` + "`" + `, ` + "`" + `r.Post` + "`" + `, etc.).
- Convert Flask ` + "`" + `Blueprint` + "`" + ` to chi ` + "`" + `r.Route` + "`" + ` or ` + "`" + `r.Group` + "`" + ` sub-routers.
- Replace ` + "`" + `request.args` + "`" + ` / ` + "`" + `request.form` + "`" + ` / ` + "`" + `request.json` + "`" + ` with ` + "`" + `r.URL.Query()` + "`" + `, ` + "`" + `r.FormValue()` + "`" + `, or ` + "`" + `json.NewDecoder(r.Body)` + "`" + `.
- Map ` + "`" + `flask.jsonify()` + "`" + ` to ` + "`" + `json.NewEncoder(w).Encode()` + "`" + ` with ` + "`" + `w.Header().Set("Content-Type", "application/json")` + "`" + `.
- Convert Flask ` + "`" + `abort(status)` + "`" + ` to ` + "`" + `http.Error(w, message, status)` + "`" + `.
- Replace ` + "`" + `flask.g` + "`" + ` (request-scoped globals) with ` + "`" + `context.WithValue` + "`" + ` on the request context.
- Map Flask ` + "`" + `before_request` + "`" + ` / ` + "`" + `after_request` + "`" + ` hooks to chi middleware.
- Convert Flask-SQLAlchemy models to Go structs + sqlc.
- Replace ` + "`" + `flask.session` + "`" + ` with cookie-based or token-based session management.
- Map ` + "`" + `flask.url_for()` + "`" + ` to explicit path construction or a route-name registry.
- Convert Flask ` + "`" + `render_template()` + "`" + ` to ` + "`" + `html/template.ExecuteTemplate` + "`" + `.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/python/grpc.md",
			Body: `## grpc to Go Conversion Rules

- Replace ` + "`" + `grpc.server(futures.ThreadPoolExecutor())` + "`" + ` with ` + "`" + `grpc.NewServer()` + "`" + ` from ` + "`" + `google.golang.org/grpc` + "`" + `.
- Map ` + "`" + `add_XServicer_to_server(servicer, server)` + "`" + ` to ` + "`" + `pb.RegisterXServer(server, &myServer{})` + "`" + `.
- Convert Python protobuf servicer classes to Go structs implementing the generated ` + "`" + `pb.XServer` + "`" + ` interface.
- Replace ` + "`" + `grpc.insecure_channel("host:port")` + "`" + ` with ` + "`" + `grpc.NewClient("host:port", grpc.WithTransportCredentials(insecure.NewCredentials()))` + "`" + `.
- Map ` + "`" + `stub = XStub(channel)` + "`" + ` to generated client constructors ` + "`" + `pb.NewXClient(conn)` + "`" + `.
- Convert ` + "`" + `response = stub.MethodName(request)` + "`" + ` to ` + "`" + `response, err := client.MethodName(ctx, request)` + "`" + `.
- Replace ` + "`" + `grpc.ssl_channel_credentials()` + "`" + ` with ` + "`" + `credentials.NewTLS(&tls.Config{...})` + "`" + `.
- Map ` + "`" + `context.abort(grpc.StatusCode.NOT_FOUND, "message")` + "`" + ` to ` + "`" + `return nil, status.Errorf(codes.NotFound, "message")` + "`" + `.
- Convert ` + "`" + `grpc.StatusCode` + "`" + ` enum values to ` + "`" + `codes` + "`" + ` package constants (` + "`" + `codes.OK` + "`" + `, ` + "`" + `codes.NotFound` + "`" + `, ` + "`" + `codes.Internal` + "`" + `, etc.).
- Replace Python async/generator streaming with Go stream ` + "`" + `Send()` + "`" + ` / ` + "`" + `Recv()` + "`" + ` methods.
- Map server-side streaming (` + "`" + `yield response` + "`" + `) to ` + "`" + `stream.Send(&response)` + "`" + ` in a loop.
- Convert client-side streaming to ` + "`" + `stream.Send(&request)` + "`" + ` loop + ` + "`" + `stream.CloseAndRecv()` + "`" + `.
- Replace bidirectional streaming with concurrent ` + "`" + `Send` + "`" + `/` + "`" + `Recv` + "`" + ` goroutines.
- Map gRPC interceptors (Python) to Go ` + "`" + `grpc.UnaryInterceptor` + "`" + ` / ` + "`" + `grpc.StreamInterceptor` + "`" + `.
- Convert ` + "`" + `grpc.reflection` + "`" + ` to ` + "`" + `google.golang.org/grpc/reflection` + "`" + `.
- Replace ` + "`" + `grpc_health` + "`" + ` to ` + "`" + `google.golang.org/grpc/health` + "`" + `.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/python/hashlib.md",
			Body: `## hashlib to Go Conversion Rules

- Replace ` + "`" + `import hashlib` + "`" + ` with the appropriate ` + "`" + `crypto/*` + "`" + ` package imports.
- Map ` + "`" + `hashlib.md5()` + "`" + ` to ` + "`" + `md5.New()` + "`" + ` from ` + "`" + `crypto/md5` + "`" + `.
- Convert ` + "`" + `hashlib.sha1()` + "`" + ` to ` + "`" + `sha1.New()` + "`" + ` from ` + "`" + `crypto/sha1` + "`" + `.
- Replace ` + "`" + `hashlib.sha256()` + "`" + ` to ` + "`" + `sha256.New()` + "`" + ` from ` + "`" + `crypto/sha256` + "`" + `.
- Map ` + "`" + `hashlib.sha512()` + "`" + ` to ` + "`" + `sha512.New()` + "`" + ` from ` + "`" + `crypto/sha512` + "`" + `.
- Convert ` + "`" + `h.update(data)` + "`" + ` to ` + "`" + `h.Write([]byte(data))` + "`" + `.
- Replace ` + "`" + `h.hexdigest()` + "`" + ` with ` + "`" + `hex.EncodeToString(h.Sum(nil))` + "`" + ` from ` + "`" + `encoding/hex` + "`" + `.
- Map ` + "`" + `h.digest()` + "`" + ` to ` + "`" + `h.Sum(nil)` + "`" + ` (returns ` + "`" + `[]byte` + "`" + `).
- Convert ` + "`" + `hashlib.new("sha256", data).hexdigest()` + "`" + ` one-liner to ` + "`" + `h := sha256.Sum256(data)` + "`" + ` + ` + "`" + `hex.EncodeToString(h[:])` + "`" + `.
- Replace ` + "`" + `hashlib.pbkdf2_hmac("sha256", password, salt, iterations)` + "`" + ` with ` + "`" + `pbkdf2.Key(password, salt, iterations, keyLen, sha256.New)` + "`" + ` from ` + "`" + `golang.org/x/crypto/pbkdf2` + "`" + `.
- Map ` + "`" + `hashlib.scrypt(password, salt=s, n=N, r=R, p=P)` + "`" + ` to ` + "`" + `scrypt.Key(password, salt, N, R, P, keyLen)` + "`" + ` from ` + "`" + `golang.org/x/crypto/scrypt` + "`" + `.
- Convert ` + "`" + `hashlib.blake2b()` + "`" + ` / ` + "`" + `hashlib.blake2s()` + "`" + ` to ` + "`" + `golang.org/x/crypto/blake2b` + "`" + ` / ` + "`" + `blake2s` + "`" + `.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/python/httpx.md",
			Body: `## httpx to Go Conversion Rules

- Replace ` + "`" + `httpx.Client()` + "`" + ` with ` + "`" + `http.Client{}` + "`" + ` from ` + "`" + `net/http` + "`" + `.
- Map ` + "`" + `httpx.AsyncClient()` + "`" + ` to the same ` + "`" + `http.Client{}` + "`" + ` — Go's client is concurrent by default.
- Convert ` + "`" + `client.get(url)` + "`" + ` to ` + "`" + `client.Get(url)` + "`" + ` or ` + "`" + `http.NewRequest` + "`" + ` + ` + "`" + `client.Do()` + "`" + `.
- Replace ` + "`" + `client.post(url, json=data)` + "`" + ` with ` + "`" + `http.Post(url, "application/json", body)` + "`" + `.
- Map ` + "`" + `response.json()` + "`" + ` to ` + "`" + `json.NewDecoder(resp.Body).Decode(&target)` + "`" + `.
- Convert ` + "`" + `response.text` + "`" + ` to ` + "`" + `io.ReadAll(resp.Body)` + "`" + ` + ` + "`" + `string(body)` + "`" + `.
- Replace ` + "`" + `response.status_code` + "`" + ` with ` + "`" + `resp.StatusCode` + "`" + `.
- Map ` + "`" + `httpx.Timeout(connect=5, read=10)` + "`" + ` to ` + "`" + `http.Client{Timeout: 10 * time.Second}` + "`" + ` with custom ` + "`" + `http.Transport{DialContext: ...}` + "`" + ` for connect timeout.
- Convert ` + "`" + `httpx.Limits(max_connections=100)` + "`" + ` to ` + "`" + `http.Transport{MaxConnsPerHost: 100}` + "`" + `.
- Replace ` + "`" + `async with httpx.AsyncClient() as client:` + "`" + ` with a reusable ` + "`" + `http.Client` + "`" + ` variable.
- Map HTTP/2 support (` + "`" + `http2=True` + "`" + `) to ` + "`" + `golang.org/x/net/http2` + "`" + ` transport configuration.
- Convert ` + "`" + `httpx.stream("GET", url)` + "`" + ` to ` + "`" + `resp, _ := client.Get(url)` + "`" + ` + reading ` + "`" + `resp.Body` + "`" + ` incrementally with ` + "`" + `bufio.Scanner` + "`" + `.
- Replace ` + "`" + `client.follow_redirects = False` + "`" + ` with ` + "`" + `client.CheckRedirect = func(...) error { return http.ErrUseLastResponse }` + "`" + `.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/python/jinja2.md",
			Body: `## Jinja2 to Go Conversion Rules

- Replace ` + "`" + `jinja2.Environment(loader=FileSystemLoader("templates"))` + "`" + ` with ` + "`" + `template.ParseGlob("templates/*.html")` + "`" + ` from ` + "`" + `html/template` + "`" + `.
- Map ` + "`" + `env.get_template("name.html")` + "`" + ` to ` + "`" + `tmpl.Lookup("name.html")` + "`" + ` or ` + "`" + `template.ParseFiles("templates/name.html")` + "`" + `.
- Convert ` + "`" + `template.render(key=value)` + "`" + ` to ` + "`" + `tmpl.Execute(w, data)` + "`" + ` where ` + "`" + `data` + "`" + ` is a struct or ` + "`" + `map[string]any` + "`" + `.
- Replace ` + "`" + `{{ variable }}` + "`" + ` syntax — Go uses the same ` + "`" + `{{ .Variable }}` + "`" + ` syntax (note the dot prefix).
- Map ` + "`" + `{{ variable | filter }}` + "`" + ` to Go template functions: register custom funcs via ` + "`" + `template.FuncMap` + "`" + `.
- Convert ` + "`" + `{% if condition %}...{% endif %}` + "`" + ` to ` + "`" + `{{ if .Condition }}...{{ end }}` + "`" + `.
- Replace ` + "`" + `{% for item in items %}...{% endfor %}` + "`" + ` with ` + "`" + `{{ range .Items }}...{{ end }}` + "`" + `.
- Map ` + "`" + `{% extends "base.html" %}` + "`" + ` / ` + "`" + `{% block name %}` + "`" + ` to Go's ` + "`" + `{{ template "name" . }}` + "`" + ` and ` + "`" + `{{ define "name" }}...{{ end }}` + "`" + `.
- Convert ` + "`" + `{% include "partial.html" %}` + "`" + ` to ` + "`" + `{{ template "partial" . }}` + "`" + `.
- Replace ` + "`" + `{% macro name(args) %}` + "`" + ` with a Go template function in ` + "`" + `template.FuncMap` + "`" + `.
- Map Jinja2 filters (` + "`" + `upper` + "`" + `, ` + "`" + `lower` + "`" + `, ` + "`" + `title` + "`" + `, ` + "`" + `trim` + "`" + `, ` + "`" + `join` + "`" + `, ` + "`" + `length` + "`" + `) to Go ` + "`" + `FuncMap` + "`" + ` entries using ` + "`" + `strings` + "`" + ` package functions.
- Convert ` + "`" + `{% set var = expr %}` + "`" + ` to ` + "`" + `{{ $var := .Expr }}` + "`" + ` Go template variables.
- Replace ` + "`" + `{{ url_for("endpoint") }}` + "`" + ` with explicit path strings or a route helper in ` + "`" + `FuncMap` + "`" + `.
- Map ` + "`" + `{% autoescape %}` + "`" + ` — ` + "`" + `html/template` + "`" + ` auto-escapes by default; use ` + "`" + `text/template` + "`" + ` for non-HTML output.
- Convert Jinja2 ` + "`" + `|safe` + "`" + ` filter to ` + "`" + `template.HTML()` + "`" + ` type cast to mark content as safe.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/python/json.md",
			Body: `## json to Go Conversion Rules

- Replace ` + "`" + `import json` + "`" + ` with ` + "`" + `import "encoding/json"` + "`" + `.
- Map ` + "`" + `json.dumps(obj)` + "`" + ` to ` + "`" + `json.Marshal(obj)` + "`" + ` (returns ` + "`" + `[]byte, error` + "`" + `).
- Convert ` + "`" + `json.dumps(obj, indent=2)` + "`" + ` to ` + "`" + `json.MarshalIndent(obj, "", "  ")` + "`" + `.
- Replace ` + "`" + `json.loads(string)` + "`" + ` with ` + "`" + `json.Unmarshal([]byte(string), &target)` + "`" + `.
- Map ` + "`" + `json.load(file)` + "`" + ` to ` + "`" + `json.NewDecoder(file).Decode(&target)` + "`" + `.
- Convert ` + "`" + `json.dump(obj, file)` + "`" + ` to ` + "`" + `json.NewEncoder(file).Encode(obj)` + "`" + `.
- Replace Python dict result with Go structs using ` + "`" + `json:"field_name"` + "`" + ` struct tags, or ` + "`" + `map[string]any` + "`" + ` for dynamic JSON.
- Map ` + "`" + `json.dumps(obj, default=str)` + "`" + ` custom serializers to implementing ` + "`" + `json.Marshaler` + "`" + ` interface on custom types.
- Convert ` + "`" + `json.JSONDecoder` + "`" + ` with custom ` + "`" + `object_hook` + "`" + ` to ` + "`" + `json.Unmarshal` + "`" + ` into a struct or custom ` + "`" + `json.Unmarshaler` + "`" + `.
- Replace ` + "`" + `json.dumps(obj, sort_keys=True)` + "`" + ` — Go's ` + "`" + `json.Marshal` + "`" + ` sorts map keys by default.
- Map ` + "`" + `json.dumps(obj, ensure_ascii=False)` + "`" + ` — Go's ` + "`" + `json.Marshal` + "`" + ` outputs UTF-8 by default, use ` + "`" + `encoder.SetEscapeHTML(false)` + "`" + ` to avoid escaping ` + "`" + `<` + "`" + `, ` + "`" + `>` + "`" + `, ` + "`" + `&` + "`" + `.
- Convert optional/nullable JSON fields to pointer types (` + "`" + `*string` + "`" + `, ` + "`" + `*int` + "`" + `) with ` + "`" + `json:"field,omitempty"` + "`" + `.
- Replace ` + "`" + `json.JSONDecodeError` + "`" + ` exception handling with ` + "`" + `err != nil` + "`" + ` checks on ` + "`" + `Unmarshal` + "`" + `.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/python/logging.md",
			Body: `## logging to Go Conversion Rules

- Replace ` + "`" + `import logging` + "`" + ` with ` + "`" + `import "log/slog"` + "`" + `.
- Map ` + "`" + `logging.getLogger(__name__)` + "`" + ` to ` + "`" + `slog.Default()` + "`" + ` or a named logger via ` + "`" + `slog.New(handler)` + "`" + `.
- Convert ` + "`" + `logging.basicConfig(level=logging.INFO)` + "`" + ` to ` + "`" + `slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))` + "`" + `.
- Replace ` + "`" + `logger.debug(msg)` + "`" + ` with ` + "`" + `slog.Debug(msg)` + "`" + `.
- Map ` + "`" + `logger.info(msg)` + "`" + ` to ` + "`" + `slog.Info(msg)` + "`" + `.
- Convert ` + "`" + `logger.warning(msg)` + "`" + ` to ` + "`" + `slog.Warn(msg)` + "`" + `.
- Replace ` + "`" + `logger.error(msg)` + "`" + ` with ` + "`" + `slog.Error(msg)` + "`" + `.
- Map ` + "`" + `logger.critical(msg)` + "`" + ` to ` + "`" + `slog.Error(msg)` + "`" + ` (Go has no critical level; add ` + "`" + `"severity", "CRITICAL"` + "`" + ` attribute if needed).
- Convert ` + "`" + `logger.info("user %s logged in", user_id)` + "`" + ` to ` + "`" + `slog.Info("user logged in", "user_id", userID)` + "`" + ` (structured key-value pairs).
- Replace ` + "`" + `logger.exception("failed")` + "`" + ` with ` + "`" + `slog.Error("failed", "error", err)` + "`" + `.
- Map ` + "`" + `logging.FileHandler("app.log")` + "`" + ` to ` + "`" + `slog.NewJSONHandler(file, nil)` + "`" + ` where ` + "`" + `file` + "`" + ` is from ` + "`" + `os.OpenFile` + "`" + `.
- Convert ` + "`" + `logging.StreamHandler()` + "`" + ` to ` + "`" + `slog.NewTextHandler(os.Stderr, nil)` + "`" + `.
- Replace ` + "`" + `logging.Formatter("%(asctime)s %(levelname)s %(message)s")` + "`" + ` with ` + "`" + `slog.HandlerOptions` + "`" + ` and custom handler attributes.
- Map ` + "`" + `logger.addHandler(handler)` + "`" + ` to constructing a ` + "`" + `slog.New(handler)` + "`" + ` logger.
- Convert ` + "`" + `extra={"key": "val"}` + "`" + ` in log calls to slog key-value pairs: ` + "`" + `slog.Info("msg", "key", "val")` + "`" + `.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/python/multiprocessing.md",
			Body: `## multiprocessing to Go Conversion Rules

WARNING: Python's ` + "`" + `multiprocessing` + "`" + ` uses OS-level processes with shared-memory IPC. Go does not have an equivalent process-based parallelism model. Convert to goroutines where possible.

- Replace ` + "`" + `multiprocessing.Process(target=func, args=(...))` + "`" + ` with ` + "`" + `go func(...) { ... }(...)` + "`" + ` goroutine launches.
- Map ` + "`" + `process.start()` + "`" + ` + ` + "`" + `process.join()` + "`" + ` to goroutines + ` + "`" + `sync.WaitGroup` + "`" + `.
- Convert ` + "`" + `multiprocessing.Pool(N)` + "`" + ` with ` + "`" + `pool.map(func, items)` + "`" + ` to ` + "`" + `errgroup.Group` + "`" + ` with bounded concurrency using a semaphore channel.
- Replace ` + "`" + `multiprocessing.Queue()` + "`" + ` with Go channels (` + "`" + `make(chan T, bufferSize)` + "`" + `).
- Map ` + "`" + `multiprocessing.Pipe()` + "`" + ` to a pair of channels or ` + "`" + `io.Pipe()` + "`" + `.
- Convert ` + "`" + `multiprocessing.Value` + "`" + ` / ` + "`" + `multiprocessing.Array` + "`" + ` (shared memory) to ` + "`" + `sync.Mutex` + "`" + `-protected variables or ` + "`" + `sync/atomic` + "`" + ` operations.
- Replace ` + "`" + `multiprocessing.Lock()` + "`" + ` with ` + "`" + `sync.Mutex` + "`" + `.
- Map ` + "`" + `multiprocessing.Manager()` + "`" + ` shared objects to struct fields protected by ` + "`" + `sync.RWMutex` + "`" + `.
- Convert ` + "`" + `pool.starmap(func, args_list)` + "`" + ` to a goroutine-per-item pattern with ` + "`" + `errgroup.Group` + "`" + `.
- Replace ` + "`" + `pool.apply_async(func, args)` + "`" + ` with a goroutine that sends the result on a channel.
- Map ` + "`" + `pool.imap_unordered(func, items)` + "`" + ` to fan-out goroutines writing to a shared results channel.
- Convert CPU-bound parallelism — set ` + "`" + `GOMAXPROCS` + "`" + ` (defaults to number of CPUs) and use goroutines.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/python/pathlib.md",
			Body: `## pathlib to Go Conversion Rules

- Replace ` + "`" + `from pathlib import Path` + "`" + ` with ` + "`" + `import "path/filepath"` + "`" + ` and ` + "`" + `import "os"` + "`" + `.
- Map ` + "`" + `Path("dir") / "file.txt"` + "`" + ` to ` + "`" + `filepath.Join("dir", "file.txt")` + "`" + `.
- Convert ` + "`" + `path.exists()` + "`" + ` to ` + "`" + `_, err := os.Stat(path); !os.IsNotExist(err)` + "`" + `.
- Replace ` + "`" + `path.is_file()` + "`" + ` with ` + "`" + `info, err := os.Stat(path); err == nil && !info.IsDir()` + "`" + `.
- Map ` + "`" + `path.is_dir()` + "`" + ` to ` + "`" + `info, err := os.Stat(path); err == nil && info.IsDir()` + "`" + `.
- Convert ` + "`" + `path.mkdir(parents=True, exist_ok=True)` + "`" + ` to ` + "`" + `os.MkdirAll(path, 0o755)` + "`" + `.
- Replace ` + "`" + `path.read_text()` + "`" + ` with ` + "`" + `os.ReadFile(path)` + "`" + ` + ` + "`" + `string(data)` + "`" + `.
- Map ` + "`" + `path.write_text(content)` + "`" + ` to ` + "`" + `os.WriteFile(path, []byte(content), 0o644)` + "`" + `.
- Convert ` + "`" + `path.read_bytes()` + "`" + ` to ` + "`" + `os.ReadFile(path)` + "`" + `.
- Replace ` + "`" + `path.write_bytes(data)` + "`" + ` with ` + "`" + `os.WriteFile(path, data, 0o644)` + "`" + `.
- Map ` + "`" + `path.name` + "`" + ` to ` + "`" + `filepath.Base(path)` + "`" + `.
- Convert ` + "`" + `path.stem` + "`" + ` to ` + "`" + `strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))` + "`" + `.
- Replace ` + "`" + `path.suffix` + "`" + ` with ` + "`" + `filepath.Ext(path)` + "`" + `.
- Map ` + "`" + `path.parent` + "`" + ` to ` + "`" + `filepath.Dir(path)` + "`" + `.
- Convert ` + "`" + `path.resolve()` + "`" + ` to ` + "`" + `filepath.Abs(path)` + "`" + `.
- Replace ` + "`" + `path.glob("*.txt")` + "`" + ` with ` + "`" + `filepath.Glob(filepath.Join(dir, "*.txt"))` + "`" + `.
- Map ` + "`" + `path.rglob("*.py")` + "`" + ` to ` + "`" + `filepath.WalkDir` + "`" + ` with extension filtering.
- Convert ` + "`" + `path.iterdir()` + "`" + ` to ` + "`" + `os.ReadDir(path)` + "`" + `.
- Replace ` + "`" + `path.rename(new)` + "`" + ` with ` + "`" + `os.Rename(old, new)` + "`" + `.
- Map ` + "`" + `path.unlink()` + "`" + ` to ` + "`" + `os.Remove(path)` + "`" + `.
- Convert ` + "`" + `path.rmdir()` + "`" + ` to ` + "`" + `os.Remove(path)` + "`" + ` (empty dir) or ` + "`" + `os.RemoveAll(path)` + "`" + ` (recursive).
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/python/pydantic.md",
			Body: `## Pydantic to Go Conversion Rules

- Replace ` + "`" + `BaseModel` + "`" + ` subclasses with Go structs + JSON struct tags (` + "`" + `json:"field_name"` + "`" + `).
- Map Pydantic field types to Go types: ` + "`" + `str` + "`" + ` → ` + "`" + `string` + "`" + `, ` + "`" + `int` + "`" + ` → ` + "`" + `int` + "`" + `, ` + "`" + `float` + "`" + ` → ` + "`" + `float64` + "`" + `, ` + "`" + `bool` + "`" + ` → ` + "`" + `bool` + "`" + `, ` + "`" + `datetime` + "`" + ` → ` + "`" + `time.Time` + "`" + `, ` + "`" + `UUID` + "`" + ` → ` + "`" + `uuid.UUID` + "`" + `, ` + "`" + `Decimal` + "`" + ` → ` + "`" + `decimal.Decimal` + "`" + `.
- Convert ` + "`" + `Optional[T]` + "`" + ` / ` + "`" + `T | None` + "`" + ` fields to pointer types (` + "`" + `*T` + "`" + `) in Go.
- Replace ` + "`" + `Field(default=val)` + "`" + ` with Go struct field defaults set in constructor functions.
- Map ` + "`" + `Field(alias="name")` + "`" + ` to ` + "`" + `json:"name"` + "`" + ` struct tags.
- Convert ` + "`" + `@validator` + "`" + ` / ` + "`" + `@field_validator` + "`" + ` methods to ` + "`" + `go-playground/validator` + "`" + ` struct tags or custom validation functions.
- Replace ` + "`" + `@root_validator` + "`" + ` with a ` + "`" + `Validate() error` + "`" + ` method on the struct.
- Map ` + "`" + `model.dict()` + "`" + ` / ` + "`" + `model.model_dump()` + "`" + ` to ` + "`" + `json.Marshal()` + "`" + ` or manual map construction.
- Convert ` + "`" + `model.json()` + "`" + ` / ` + "`" + `model.model_dump_json()` + "`" + ` to ` + "`" + `json.Marshal()` + "`" + `.
- Replace ` + "`" + `Model.parse_obj()` + "`" + ` / ` + "`" + `Model.model_validate()` + "`" + ` with ` + "`" + `json.Unmarshal()` + "`" + ` + validation.
- Map ` + "`" + `constr(min_length=N, max_length=M)` + "`" + ` to validator tags ` + "`" + `validate:"min=N,max=M"` + "`" + `.
- Convert ` + "`" + `conint(ge=0, le=100)` + "`" + ` to validator tags ` + "`" + `validate:"gte=0,lte=100"` + "`" + `.
- Replace ` + "`" + `EmailStr` + "`" + ` with ` + "`" + `validate:"email"` + "`" + ` tag.
- Map ` + "`" + `HttpUrl` + "`" + ` to ` + "`" + `validate:"url"` + "`" + ` tag or ` + "`" + `url.Parse()` + "`" + ` validation.
- Convert nested Pydantic models to nested Go structs.
- Replace ` + "`" + `model_config = ConfigDict(...)` + "`" + ` settings with struct tag conventions.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/python/pytest.md",
			Body: `## pytest to Go Conversion Rules

- Replace ` + "`" + `def test_name(self):` + "`" + ` or ` + "`" + `def test_name():` + "`" + ` with ` + "`" + `func TestName(t *testing.T)` + "`" + `.
- Map ` + "`" + `assert expression` + "`" + ` to ` + "`" + `if !expression { t.Error(...) }` + "`" + ` or ` + "`" + `testify` + "`" + ` assertions (` + "`" + `assert.True` + "`" + `, ` + "`" + `assert.Equal` + "`" + `).
- Convert ` + "`" + `assert a == b` + "`" + ` to ` + "`" + `assert.Equal(t, expected, actual)` + "`" + ` or ` + "`" + `if got != want { t.Errorf(...) }` + "`" + `.
- Replace ` + "`" + `assert a != b` + "`" + ` with ` + "`" + `assert.NotEqual(t, a, b)` + "`" + `.
- Map ` + "`" + `pytest.raises(ExceptionType)` + "`" + ` to checking ` + "`" + `err != nil` + "`" + ` and ` + "`" + `errors.Is` + "`" + ` / ` + "`" + `errors.As` + "`" + `.
- Convert ` + "`" + `@pytest.fixture` + "`" + ` to test helper functions or ` + "`" + `TestMain(m *testing.M)` + "`" + ` setup/teardown.
- Replace ` + "`" + `@pytest.fixture(scope="module")` + "`" + ` with ` + "`" + `TestMain` + "`" + ` for package-level setup.
- Map ` + "`" + `@pytest.mark.parametrize` + "`" + ` to table-driven tests with ` + "`" + `[]struct{ ... }` + "`" + ` test cases.
- Convert ` + "`" + `conftest.py` + "`" + ` shared fixtures to test helper packages or ` + "`" + `testutil` + "`" + ` functions.
- Replace ` + "`" + `@pytest.mark.skip` + "`" + ` / ` + "`" + `@pytest.mark.skipif` + "`" + ` with ` + "`" + `t.Skip()` + "`" + ` / ` + "`" + `t.Skipf()` + "`" + `.
- Map ` + "`" + `@pytest.mark.xfail` + "`" + ` to conditional ` + "`" + `t.Skip("known failure: ...")` + "`" + `.
- Convert ` + "`" + `monkeypatch.setattr()` + "`" + ` to interface-based dependency injection for testability.
- Replace ` + "`" + `tmp_path` + "`" + ` / ` + "`" + `tmpdir` + "`" + ` fixtures with ` + "`" + `t.TempDir()` + "`" + `.
- Map ` + "`" + `capfd` + "`" + ` / ` + "`" + `capsys` + "`" + ` (output capture) to redirecting ` + "`" + `os.Stdout` + "`" + ` or using ` + "`" + `bytes.Buffer` + "`" + `.
- Convert ` + "`" + `@pytest.mark.timeout(N)` + "`" + ` to ` + "`" + `context.WithTimeout` + "`" + ` in the test.
- Replace ` + "`" + `pytest.approx(val)` + "`" + ` with ` + "`" + `math.Abs(got-want) < epsilon` + "`" + ` comparisons.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/python/re.md",
			Body: `## re (regex) to Go Conversion Rules

- Replace ` + "`" + `import re` + "`" + ` with ` + "`" + `import "regexp"` + "`" + `.
- Map ` + "`" + `re.compile(pattern)` + "`" + ` to ` + "`" + `regexp.MustCompile(pattern)` + "`" + ` (panics on invalid pattern) or ` + "`" + `regexp.Compile(pattern)` + "`" + ` (returns error).
- Convert ` + "`" + `re.search(pattern, text)` + "`" + ` to ` + "`" + `re.FindString(text)` + "`" + ` or ` + "`" + `re.FindStringIndex(text)` + "`" + `.
- Replace ` + "`" + `re.match(pattern, text)` + "`" + ` — note: Go's ` + "`" + `regexp` + "`" + ` does not anchor at start by default. Use ` + "`" + `regexp.MustCompile("^" + pattern)` + "`" + ` for match-at-start behavior.
- Map ` + "`" + `re.findall(pattern, text)` + "`" + ` to ` + "`" + `re.FindAllString(text, -1)` + "`" + `.
- Convert ` + "`" + `re.finditer(pattern, text)` + "`" + ` to ` + "`" + `re.FindAllStringIndex(text, -1)` + "`" + ` or ` + "`" + `re.FindAllStringSubmatch(text, -1)` + "`" + `.
- Replace ` + "`" + `re.sub(pattern, repl, text)` + "`" + ` with ` + "`" + `re.ReplaceAllString(text, repl)` + "`" + `.
- Map ` + "`" + `re.split(pattern, text)` + "`" + ` to ` + "`" + `re.Split(text, -1)` + "`" + `.
- Convert named groups ` + "`" + `(?P<name>...)` + "`" + ` — Go supports this syntax: ` + "`" + `re.SubexpNames()` + "`" + ` + ` + "`" + `re.FindStringSubmatch(text)` + "`" + `.
- Replace ` + "`" + `match.group(0)` + "`" + ` with full match return, ` + "`" + `match.group(1)` + "`" + ` with submatch index.
- Map ` + "`" + `re.IGNORECASE` + "`" + ` / ` + "`" + `re.I` + "`" + ` flag to ` + "`" + `(?i)` + "`" + ` prefix in the pattern string.
- Convert ` + "`" + `re.MULTILINE` + "`" + ` / ` + "`" + `re.M` + "`" + ` to ` + "`" + `(?m)` + "`" + ` prefix.
- Replace ` + "`" + `re.DOTALL` + "`" + ` / ` + "`" + `re.S` + "`" + ` to ` + "`" + `(?s)` + "`" + ` prefix.
- Note: Go uses RE2 syntax which does NOT support lookahead ` + "`" + `(?=...)` + "`" + `, lookbehind ` + "`" + `(?<=...)` + "`" + `, or backreferences ` + "`" + `\1` + "`" + `. If the Python regex uses these, flag it as requiring manual rewrite.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/python/redis.md",
			Body: `## redis to Go Conversion Rules

- Replace ` + "`" + `redis.Redis(host, port, db)` + "`" + ` with ` + "`" + `redis.NewClient(&redis.Options{Addr: "host:port", DB: db})` + "`" + ` from ` + "`" + `github.com/redis/go-redis/v9` + "`" + `.
- Map ` + "`" + `redis.ConnectionPool()` + "`" + ` to ` + "`" + `redis.Options` + "`" + ` with ` + "`" + `PoolSize` + "`" + ` and ` + "`" + `MinIdleConns` + "`" + ` fields (pooling is built-in).
- Convert ` + "`" + `r.set("key", "value")` + "`" + ` to ` + "`" + `client.Set(ctx, "key", "value", 0).Err()` + "`" + `.
- Replace ` + "`" + `r.get("key")` + "`" + ` with ` + "`" + `client.Get(ctx, "key").Result()` + "`" + ` — handle ` + "`" + `redis.Nil` + "`" + ` for missing keys.
- Map ` + "`" + `r.delete("key")` + "`" + ` to ` + "`" + `client.Del(ctx, "key").Err()` + "`" + `.
- Convert ` + "`" + `r.exists("key")` + "`" + ` to ` + "`" + `client.Exists(ctx, "key").Result()` + "`" + `.
- Replace ` + "`" + `r.expire("key", seconds)` + "`" + ` with ` + "`" + `client.Expire(ctx, "key", time.Duration(seconds)*time.Second).Err()` + "`" + `.
- Map ` + "`" + `r.hset()` + "`" + ` / ` + "`" + `r.hget()` + "`" + ` / ` + "`" + `r.hgetall()` + "`" + ` to ` + "`" + `client.HSet()` + "`" + ` / ` + "`" + `client.HGet()` + "`" + ` / ` + "`" + `client.HGetAll()` + "`" + `.
- Convert ` + "`" + `r.lpush()` + "`" + ` / ` + "`" + `r.rpush()` + "`" + ` / ` + "`" + `r.lpop()` + "`" + ` / ` + "`" + `r.rpop()` + "`" + ` to ` + "`" + `client.LPush()` + "`" + ` / ` + "`" + `client.RPush()` + "`" + ` / ` + "`" + `client.LPop()` + "`" + ` / ` + "`" + `client.RPop()` + "`" + `.
- Replace ` + "`" + `r.sadd()` + "`" + ` / ` + "`" + `r.smembers()` + "`" + ` with ` + "`" + `client.SAdd()` + "`" + ` / ` + "`" + `client.SMembers()` + "`" + `.
- Map ` + "`" + `r.zadd()` + "`" + ` / ` + "`" + `r.zrangebyscore()` + "`" + ` to ` + "`" + `client.ZAdd()` + "`" + ` / ` + "`" + `client.ZRangeByScore()` + "`" + `.
- Convert ` + "`" + `r.pipeline()` + "`" + ` to ` + "`" + `client.Pipeline()` + "`" + ` or ` + "`" + `client.TxPipeline()` + "`" + ` for transactions.
- Replace ` + "`" + `r.pubsub()` + "`" + ` with ` + "`" + `client.Subscribe(ctx, "channel")` + "`" + ` and ` + "`" + `pubsub.ReceiveMessage(ctx)` + "`" + `.
- Map ` + "`" + `r.lock("name")` + "`" + ` (redis-py distributed lock) to ` + "`" + `github.com/bsm/redislock` + "`" + `.
- Convert ` + "`" + `aioredis` + "`" + ` async operations to the same ` + "`" + `go-redis` + "`" + ` client (it supports context-based cancellation natively).
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/python/requests.md",
			Body: `## requests / httpx to Go Conversion Rules

- Replace ` + "`" + `requests.get(url)` + "`" + ` with ` + "`" + `http.Get(url)` + "`" + ` or ` + "`" + `http.NewRequest` + "`" + ` + ` + "`" + `client.Do()` + "`" + `.
- Map ` + "`" + `requests.post(url, json=data)` + "`" + ` to ` + "`" + `http.Post(url, "application/json", body)` + "`" + ` with ` + "`" + `json.Marshal` + "`" + ` for the body.
- Convert ` + "`" + `requests.put()` + "`" + `, ` + "`" + `requests.patch()` + "`" + `, ` + "`" + `requests.delete()` + "`" + ` to ` + "`" + `http.NewRequest(method, url, body)` + "`" + ` + ` + "`" + `client.Do()` + "`" + `.
- Replace ` + "`" + `response.json()` + "`" + ` with ` + "`" + `json.NewDecoder(resp.Body).Decode(&target)` + "`" + `.
- Map ` + "`" + `response.text` + "`" + ` to ` + "`" + `io.ReadAll(resp.Body)` + "`" + ` + ` + "`" + `string(body)` + "`" + `.
- Convert ` + "`" + `response.status_code` + "`" + ` to ` + "`" + `resp.StatusCode` + "`" + `.
- Replace ` + "`" + `response.headers` + "`" + ` to ` + "`" + `resp.Header.Get("key")` + "`" + `.
- Map ` + "`" + `requests.Session()` + "`" + ` to a reusable ` + "`" + `http.Client` + "`" + ` with configured transport, timeout, and cookie jar.
- Convert ` + "`" + `session.auth = (user, pass)` + "`" + ` to ` + "`" + `req.SetBasicAuth(user, pass)` + "`" + `.
- Replace ` + "`" + `params={"key": "val"}` + "`" + ` query parameters with ` + "`" + `url.Values` + "`" + ` and ` + "`" + `req.URL.RawQuery = params.Encode()` + "`" + `.
- Map ` + "`" + `headers={"key": "val"}` + "`" + ` to ` + "`" + `req.Header.Set("key", "val")` + "`" + `.
- Convert ` + "`" + `timeout=N` + "`" + ` to ` + "`" + `http.Client{Timeout: N * time.Second}` + "`" + `.
- Replace ` + "`" + `files={"file": open("f")}` + "`" + ` with ` + "`" + `multipart.NewWriter` + "`" + ` for file uploads.
- Map ` + "`" + `requests.exceptions.ConnectionError` + "`" + ` / ` + "`" + `Timeout` + "`" + ` to ` + "`" + `net` + "`" + ` package errors and ` + "`" + `os.IsTimeout()` + "`" + `.
- Convert ` + "`" + `response.raise_for_status()` + "`" + ` to explicit ` + "`" + `if resp.StatusCode >= 400 { return fmt.Errorf(...) }` + "`" + ` checks.
- Replace ` + "`" + `allow_redirects=False` + "`" + ` with ` + "`" + `client.CheckRedirect` + "`" + ` function.
- Map ` + "`" + `verify=False` + "`" + ` (disable TLS verification) to custom ` + "`" + `http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}` + "`" + ` — add a security warning comment.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/python/sqlalchemy.md",
			Body: `## SQLAlchemy to Go Conversion Rules

- Replace ` + "`" + `declarative_base()` + "`" + ` model definitions with plain Go structs + ` + "`" + `db` + "`" + ` struct tags for column mapping.
- Map SQLAlchemy ` + "`" + `Column(Type)` + "`" + ` declarations to Go struct fields with appropriate types (` + "`" + `Integer` + "`" + ` → ` + "`" + `int` + "`" + `, ` + "`" + `String(N)` + "`" + ` → ` + "`" + `string` + "`" + `, ` + "`" + `Boolean` + "`" + ` → ` + "`" + `bool` + "`" + `, ` + "`" + `DateTime` + "`" + ` → ` + "`" + `time.Time` + "`" + `, ` + "`" + `Float` + "`" + ` → ` + "`" + `float64` + "`" + `, ` + "`" + `Text` + "`" + ` → ` + "`" + `string` + "`" + `, ` + "`" + `Numeric` + "`" + ` → ` + "`" + `decimal.Decimal` + "`" + `).
- Convert SQLAlchemy ` + "`" + `relationship()` + "`" + ` and ` + "`" + `ForeignKey` + "`" + ` to separate Go structs with explicit JOIN queries.
- Replace ` + "`" + `session.query(Model).filter()` + "`" + ` chains with raw SQL queries via ` + "`" + `sqlc` + "`" + ` or ` + "`" + `database/sql` + "`" + `.
- Map ` + "`" + `.filter(Model.col == val)` + "`" + ` to SQL ` + "`" + `WHERE col = $1` + "`" + ` with parameterized queries.
- Convert ` + "`" + `.filter(Model.col.in_(list))` + "`" + ` to ` + "`" + `WHERE col = ANY($1)` + "`" + ` with ` + "`" + `pq.Array()` + "`" + ` or equivalent.
- Replace ` + "`" + `.order_by()` + "`" + `, ` + "`" + `.limit()` + "`" + `, ` + "`" + `.offset()` + "`" + ` with SQL ` + "`" + `ORDER BY` + "`" + `, ` + "`" + `LIMIT` + "`" + `, ` + "`" + `OFFSET` + "`" + ` clauses.
- Map ` + "`" + `.join()` + "`" + ` / ` + "`" + `.outerjoin()` + "`" + ` to explicit SQL ` + "`" + `JOIN` + "`" + ` / ` + "`" + `LEFT JOIN` + "`" + ` statements.
- Convert ` + "`" + `session.add()` + "`" + ` / ` + "`" + `session.commit()` + "`" + ` to ` + "`" + `db.ExecContext()` + "`" + ` with explicit ` + "`" + `INSERT` + "`" + ` statements.
- Replace ` + "`" + `session.delete()` + "`" + ` with ` + "`" + `DELETE FROM table WHERE id = $1` + "`" + `.
- Map SQLAlchemy migrations (Alembic) to ` + "`" + `golang-migrate/migrate` + "`" + ` or ` + "`" + `pressly/goose` + "`" + `.
- Convert ` + "`" + `session.begin()` + "`" + ` / ` + "`" + `session.rollback()` + "`" + ` to ` + "`" + `db.BeginTx()` + "`" + ` / ` + "`" + `tx.Rollback()` + "`" + `.
- Replace ` + "`" + `@event.listens_for` + "`" + ` hooks with explicit pre/post function calls in the repository layer.
- Map ` + "`" + `hybrid_property` + "`" + ` to Go getter methods on the struct.
- Convert ` + "`" + `scoped_session` + "`" + ` to connection pooling via ` + "`" + `sql.DB` + "`" + ` (built-in pool) or ` + "`" + `pgxpool.Pool` + "`" + `.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/python/subprocess.md",
			Body: `## subprocess to Go Conversion Rules

- Replace ` + "`" + `import subprocess` + "`" + ` with ` + "`" + `import "os/exec"` + "`" + `.
- Map ` + "`" + `subprocess.run(["cmd", "arg1", "arg2"])` + "`" + ` to ` + "`" + `exec.Command("cmd", "arg1", "arg2").Run()` + "`" + `.
- Convert ` + "`" + `subprocess.run(cmd, capture_output=True)` + "`" + ` to ` + "`" + `exec.Command(cmd...).Output()` + "`" + ` (captures stdout) or ` + "`" + `exec.Command(cmd...).CombinedOutput()` + "`" + ` (stdout+stderr).
- Replace ` + "`" + `subprocess.run(cmd, check=True)` + "`" + ` — Go's ` + "`" + `cmd.Run()` + "`" + ` returns an error on non-zero exit; check ` + "`" + `err != nil` + "`" + `.
- Map ` + "`" + `result.stdout` + "`" + ` to the ` + "`" + `[]byte` + "`" + ` returned by ` + "`" + `cmd.Output()` + "`" + `.
- Convert ` + "`" + `result.returncode` + "`" + ` to ` + "`" + `cmd.ProcessState.ExitCode()` + "`" + ` after ` + "`" + `cmd.Run()` + "`" + `.
- Replace ` + "`" + `subprocess.Popen(cmd)` + "`" + ` with ` + "`" + `cmd := exec.Command(cmd...); cmd.Start()` + "`" + ` for long-running processes.
- Map ` + "`" + `process.communicate(input=data)` + "`" + ` to setting ` + "`" + `cmd.Stdin` + "`" + ` + ` + "`" + `cmd.Output()` + "`" + ` or pipe-based I/O.
- Convert ` + "`" + `process.wait()` + "`" + ` to ` + "`" + `cmd.Wait()` + "`" + `.
- Replace ` + "`" + `process.kill()` + "`" + ` to ` + "`" + `cmd.Process.Kill()` + "`" + `.
- Map ` + "`" + `subprocess.PIPE` + "`" + ` to ` + "`" + `cmd.StdoutPipe()` + "`" + ` / ` + "`" + `cmd.StdinPipe()` + "`" + ` / ` + "`" + `cmd.StderrPipe()` + "`" + `.
- Convert ` + "`" + `shell=True` + "`" + ` — avoid in Go; use ` + "`" + `exec.Command("sh", "-c", shellCmd)` + "`" + ` only when truly needed, with proper input sanitization.
- Replace ` + "`" + `subprocess.check_output(cmd)` + "`" + ` with ` + "`" + `exec.Command(cmd...).Output()` + "`" + `.
- Map ` + "`" + `cwd="path"` + "`" + ` to ` + "`" + `cmd.Dir = "path"` + "`" + `.
- Convert ` + "`" + `env={"KEY": "VAL"}` + "`" + ` to ` + "`" + `cmd.Env = append(os.Environ(), "KEY=VAL")` + "`" + `.
- Replace ` + "`" + `timeout=N` + "`" + ` with ` + "`" + `context.WithTimeout` + "`" + ` + ` + "`" + `exec.CommandContext(ctx, cmd...)` + "`" + `.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/python/threading.md",
			Body: `## threading to Go Conversion Rules

- Replace ` + "`" + `threading.Thread(target=func, args=(a, b))` + "`" + ` with ` + "`" + `go func(a, b) { ... }(a, b)` + "`" + ` goroutine launches.
- Map ` + "`" + `thread.start()` + "`" + ` to the goroutine launch itself (` + "`" + `go` + "`" + ` keyword).
- Convert ` + "`" + `thread.join()` + "`" + ` to ` + "`" + `sync.WaitGroup` + "`" + ` — call ` + "`" + `wg.Add(1)` + "`" + ` before launch, ` + "`" + `wg.Done()` + "`" + ` in goroutine, ` + "`" + `wg.Wait()` + "`" + ` to join.
- Replace ` + "`" + `threading.Lock()` + "`" + ` with ` + "`" + `sync.Mutex` + "`" + `.
- Map ` + "`" + `lock.acquire()` + "`" + ` / ` + "`" + `lock.release()` + "`" + ` to ` + "`" + `mu.Lock()` + "`" + ` / ` + "`" + `mu.Unlock()` + "`" + `, prefer ` + "`" + `defer mu.Unlock()` + "`" + `.
- Convert ` + "`" + `threading.RLock()` + "`" + ` to ` + "`" + `sync.RWMutex` + "`" + ` (use ` + "`" + `RLock()` + "`" + `/` + "`" + `RUnlock()` + "`" + ` for readers, ` + "`" + `Lock()` + "`" + `/` + "`" + `Unlock()` + "`" + ` for writers).
- Replace ` + "`" + `threading.Event()` + "`" + ` with a channel (` + "`" + `make(chan struct{})` + "`" + `) — ` + "`" + `event.set()` + "`" + ` → ` + "`" + `close(ch)` + "`" + `, ` + "`" + `event.wait()` + "`" + ` → ` + "`" + `<-ch` + "`" + `.
- Map ` + "`" + `threading.Semaphore(n)` + "`" + ` to a buffered channel ` + "`" + `make(chan struct{}, n)` + "`" + ` or ` + "`" + `golang.org/x/sync/semaphore` + "`" + `.
- Convert ` + "`" + `threading.Condition()` + "`" + ` to ` + "`" + `sync.Cond` + "`" + `.
- Replace ` + "`" + `threading.Timer(delay, func)` + "`" + ` with ` + "`" + `time.AfterFunc(delay, func)` + "`" + `.
- Map ` + "`" + `threading.local()` + "`" + ` (thread-local storage) to ` + "`" + `context.Value` + "`" + ` or explicit parameter passing (Go discourages goroutine-local state).
- Convert ` + "`" + `queue.Queue()` + "`" + ` (thread-safe queue) to Go channels.
- Replace ` + "`" + `threading.Barrier(n)` + "`" + ` with ` + "`" + `sync.WaitGroup` + "`" + ` or ` + "`" + `golang.org/x/sync/errgroup` + "`" + `.
- Map ` + "`" + `daemon=True` + "`" + ` thread flag to goroutines (all goroutines are daemon-like; use ` + "`" + `sync.WaitGroup` + "`" + ` if you need to wait).
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/python/toml.md",
			Body: `## toml to Go Conversion Rules

- Replace ` + "`" + `import toml` + "`" + ` or ` + "`" + `import tomllib` + "`" + ` with ` + "`" + `import "github.com/BurntSushi/toml"` + "`" + ` or ` + "`" + `import "github.com/pelletier/go-toml/v2"` + "`" + `.
- Map ` + "`" + `toml.load("file.toml")` + "`" + ` to ` + "`" + `toml.DecodeFile("file.toml", &config)` + "`" + `.
- Convert ` + "`" + `toml.loads(string)` + "`" + ` to ` + "`" + `toml.Decode(string, &config)` + "`" + `.
- Replace ` + "`" + `tomllib.load(open("file", "rb"))` + "`" + ` to ` + "`" + `toml.DecodeFile("file.toml", &config)` + "`" + `.
- Map ` + "`" + `toml.dump(data, file)` + "`" + ` to ` + "`" + `toml.NewEncoder(file).Encode(data)` + "`" + `.
- Convert ` + "`" + `toml.dumps(data)` + "`" + ` to ` + "`" + `buf := new(bytes.Buffer); toml.NewEncoder(buf).Encode(data)` + "`" + `.
- Replace Python dict result with Go structs using ` + "`" + `toml:"field_name"` + "`" + ` struct tags.
- Map nested TOML tables to nested Go structs or ` + "`" + `map[string]any` + "`" + `.
- Convert TOML arrays of tables (` + "`" + `[[section]]` + "`" + `) to Go slices of structs.
- Replace ` + "`" + `toml.TomlDecodeError` + "`" + ` exception handling with ` + "`" + `err != nil` + "`" + ` checks.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/python/unittest.md",
			Body: `## unittest to Go Conversion Rules

- Replace ` + "`" + `class TestX(unittest.TestCase):` + "`" + ` with individual ` + "`" + `func TestX(t *testing.T)` + "`" + ` functions.
- Map ` + "`" + `self.assertEqual(a, b)` + "`" + ` to ` + "`" + `if a != b { t.Errorf("got %v, want %v", a, b) }` + "`" + ` or ` + "`" + `assert.Equal(t, b, a)` + "`" + `.
- Convert ` + "`" + `self.assertNotEqual(a, b)` + "`" + ` to ` + "`" + `if a == b { t.Errorf(...) }` + "`" + ` or ` + "`" + `assert.NotEqual(t, b, a)` + "`" + `.
- Replace ` + "`" + `self.assertTrue(x)` + "`" + ` with ` + "`" + `if !x { t.Error("expected true") }` + "`" + ` or ` + "`" + `assert.True(t, x)` + "`" + `.
- Map ` + "`" + `self.assertFalse(x)` + "`" + ` to ` + "`" + `if x { t.Error("expected false") }` + "`" + ` or ` + "`" + `assert.False(t, x)` + "`" + `.
- Convert ` + "`" + `self.assertIsNone(x)` + "`" + ` to ` + "`" + `if x != nil { t.Error("expected nil") }` + "`" + ` or ` + "`" + `assert.Nil(t, x)` + "`" + `.
- Replace ` + "`" + `self.assertRaises(ExcType)` + "`" + ` with checking ` + "`" + `err != nil` + "`" + ` and ` + "`" + `errors.Is` + "`" + ` / ` + "`" + `errors.As` + "`" + `.
- Map ` + "`" + `self.assertIn(item, collection)` + "`" + ` to ` + "`" + `assert.Contains(t, collection, item)` + "`" + ` or manual loop check.
- Convert ` + "`" + `self.assertAlmostEqual(a, b, places=N)` + "`" + ` to ` + "`" + `if math.Abs(a-b) > epsilon { t.Errorf(...) }` + "`" + `.
- Replace ` + "`" + `self.assertRegex(text, pattern)` + "`" + ` with ` + "`" + `regexp.MustCompile(pattern).MatchString(text)` + "`" + `.
- Map ` + "`" + `setUp(self)` + "`" + ` to test helper functions called at the start of each test, or ` + "`" + `TestMain(m *testing.M)` + "`" + `.
- Convert ` + "`" + `tearDown(self)` + "`" + ` to ` + "`" + `defer cleanup()` + "`" + ` or ` + "`" + `t.Cleanup(func() { ... })` + "`" + `.
- Replace ` + "`" + `setUpClass` + "`" + ` / ` + "`" + `tearDownClass` + "`" + ` with ` + "`" + `TestMain(m *testing.M)` + "`" + ` for package-level setup.
- Map ` + "`" + `@unittest.skip("reason")` + "`" + ` to ` + "`" + `t.Skip("reason")` + "`" + `.
- Convert ` + "`" + `unittest.mock.patch()` + "`" + ` to interface-based dependency injection.
- Replace ` + "`" + `unittest.mock.MagicMock()` + "`" + ` with custom mock structs implementing the required interface.
- Map ` + "`" + `self.subTest(name=val)` + "`" + ` to ` + "`" + `t.Run(name, func(t *testing.T) { ... })` + "`" + `.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/python/uuid.md",
			Body: `## uuid to Go Conversion Rules

- Replace ` + "`" + `import uuid` + "`" + ` with ` + "`" + `import "github.com/google/uuid"` + "`" + `.
- Map ` + "`" + `uuid.uuid4()` + "`" + ` to ` + "`" + `uuid.New()` + "`" + ` (generates a random v4 UUID).
- Convert ` + "`" + `uuid.uuid1()` + "`" + ` to ` + "`" + `uuid.NewUUID()` + "`" + ` (v1 time-based UUID).
- Replace ` + "`" + `uuid.UUID(string)` + "`" + ` to ` + "`" + `uuid.Parse(string)` + "`" + ` (returns ` + "`" + `uuid.UUID, error` + "`" + `).
- Map ` + "`" + `str(my_uuid)` + "`" + ` to ` + "`" + `myUUID.String()` + "`" + `.
- Convert ` + "`" + `uuid.uuid5(uuid.NAMESPACE_DNS, name)` + "`" + ` to ` + "`" + `uuid.NewSHA1(uuid.NameSpaceDNS, []byte(name))` + "`" + `.
- Replace ` + "`" + `uuid.uuid3(uuid.NAMESPACE_URL, name)` + "`" + ` to ` + "`" + `uuid.NewMD5(uuid.NameSpaceURL, []byte(name))` + "`" + `.
- Map ` + "`" + `my_uuid.hex` + "`" + ` (no dashes) to ` + "`" + `strings.ReplaceAll(myUUID.String(), "-", "")` + "`" + `.
- Convert ` + "`" + `my_uuid.bytes` + "`" + ` to ` + "`" + `myUUID[:]` + "`" + ` (uuid.UUID is a ` + "`" + `[16]byte` + "`" + ` array).
- Replace ` + "`" + `uuid.UUID(bytes=b)` + "`" + ` with ` + "`" + `uuid.FromBytes(b)` + "`" + `.
- Map ` + "`" + `my_uuid == other_uuid` + "`" + ` to ` + "`" + `myUUID == otherUUID` + "`" + ` (Go UUIDs support ` + "`" + `==` + "`" + ` directly).
- Convert ` + "`" + `uuid.NAMESPACE_DNS` + "`" + `, ` + "`" + `uuid.NAMESPACE_URL` + "`" + ` to ` + "`" + `uuid.NameSpaceDNS` + "`" + `, ` + "`" + `uuid.NameSpaceURL` + "`" + `.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/python/uvicorn.md",
			Body: `## uvicorn to Go Conversion Rules

- Replace ` + "`" + `uvicorn.run(app, host="0.0.0.0", port=8000)` + "`" + ` with ` + "`" + `http.ListenAndServe(":8000", router)` + "`" + `.
- Map ` + "`" + `uvicorn.run(app, host, port, workers=N)` + "`" + ` — Go's ` + "`" + `net/http` + "`" + ` server handles concurrency via goroutines without explicit worker config.
- Convert ` + "`" + `uvicorn.run(app, ssl_keyfile=key, ssl_certfile=cert)` + "`" + ` to ` + "`" + `http.ListenAndServeTLS(":443", certFile, keyFile, router)` + "`" + `.
- Replace ` + "`" + `--reload` + "`" + ` (auto-reload on code changes) with ` + "`" + `github.com/cosmtrek/air` + "`" + ` for development.
- Map ` + "`" + `uvicorn.Config(log_level="info")` + "`" + ` to ` + "`" + `slog` + "`" + ` logger configuration.
- Convert ASGI lifespan events (` + "`" + `startup` + "`" + `, ` + "`" + `shutdown` + "`" + `) to ` + "`" + `http.Server` + "`" + ` with explicit ` + "`" + `srv.ListenAndServe()` + "`" + ` + ` + "`" + `srv.Shutdown(ctx)` + "`" + ` for graceful shutdown.
- Replace ` + "`" + `gunicorn -w 4 -k uvicorn.workers.UvicornWorker` + "`" + ` with a single Go binary (Go's runtime multiplexes goroutines across OS threads automatically).
- Map access log middleware to chi ` + "`" + `middleware.Logger` + "`" + ` or a custom logging middleware.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/python/websocket.md",
			Body: `## websocket to Go Conversion Rules

- Replace ` + "`" + `websockets.serve(handler, host, port)` + "`" + ` with an ` + "`" + `http.ServeMux` + "`" + ` + ` + "`" + `nhooyr.io/websocket` + "`" + ` accept handler.
- Map ` + "`" + `websockets.connect(url)` + "`" + ` to ` + "`" + `websocket.Dial(ctx, url, nil)` + "`" + ` from ` + "`" + `nhooyr.io/websocket` + "`" + `.
- Convert ` + "`" + `await ws.send(msg)` + "`" + ` to ` + "`" + `conn.Write(ctx, websocket.MessageText, []byte(msg))` + "`" + `.
- Replace ` + "`" + `await ws.recv()` + "`" + ` to ` + "`" + `_, msg, err := conn.Read(ctx)` + "`" + `.
- Map ` + "`" + `async for message in websocket:` + "`" + ` to a ` + "`" + `for` + "`" + ` loop calling ` + "`" + `conn.Read(ctx)` + "`" + ` until error.
- Convert ` + "`" + `websocket.ConnectionClosed` + "`" + ` exception handling to checking the error from ` + "`" + `conn.Read()` + "`" + ` / ` + "`" + `conn.Write()` + "`" + `.
- Replace ` + "`" + `ws.close()` + "`" + ` with ` + "`" + `conn.Close(websocket.StatusNormalClosure, "")` + "`" + `.
- Map ping/pong handling — ` + "`" + `nhooyr.io/websocket` + "`" + ` handles pings automatically.
- Convert ` + "`" + `websockets.broadcast(connections, msg)` + "`" + ` to iterating over a connection map and calling ` + "`" + `conn.Write` + "`" + ` for each.
- Replace connection state management (set of connected clients) with a ` + "`" + `sync.Map` + "`" + ` or mutex-protected map of connections.
- Map ` + "`" + `max_size` + "`" + ` / ` + "`" + `max_queue` + "`" + ` WebSocket options to ` + "`" + `websocket.AcceptOptions{...}` + "`" + ` fields.
- Convert WebSocket authentication (checking headers/tokens in ` + "`" + `connect` + "`" + `) to HTTP middleware that runs before the WebSocket upgrade.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/python/yaml.md",
			Body: `## yaml to Go Conversion Rules

- Replace ` + "`" + `import yaml` + "`" + ` with ` + "`" + `import "gopkg.in/yaml.v3"` + "`" + `.
- Map ` + "`" + `yaml.safe_load(data)` + "`" + ` to ` + "`" + `yaml.Unmarshal([]byte(data), &target)` + "`" + `.
- Convert ` + "`" + `yaml.safe_load(open("file"))` + "`" + ` to ` + "`" + `os.ReadFile("file")` + "`" + ` + ` + "`" + `yaml.Unmarshal(data, &target)` + "`" + `.
- Replace ` + "`" + `yaml.dump(data)` + "`" + ` with ` + "`" + `yaml.Marshal(data)` + "`" + `.
- Map ` + "`" + `yaml.dump(data, file)` + "`" + ` to ` + "`" + `yaml.Marshal(data)` + "`" + ` + ` + "`" + `os.WriteFile(path, out, 0o644)` + "`" + `.
- Convert ` + "`" + `yaml.safe_load_all(data)` + "`" + ` (multi-document) to ` + "`" + `yaml.NewDecoder(reader)` + "`" + ` with repeated ` + "`" + `decoder.Decode(&target)` + "`" + ` calls.
- Replace Python dict result with Go structs using ` + "`" + `yaml:"field_name"` + "`" + ` struct tags.
- Map ` + "`" + `yaml.add_representer()` + "`" + ` / ` + "`" + `yaml.add_constructor()` + "`" + ` to implementing ` + "`" + `yaml.Marshaler` + "`" + ` / ` + "`" + `yaml.Unmarshaler` + "`" + ` interfaces.
- Convert ` + "`" + `Loader=yaml.FullLoader` + "`" + ` / ` + "`" + `Loader=yaml.SafeLoader` + "`" + ` — Go's ` + "`" + `yaml.Unmarshal` + "`" + ` is safe by default.
- Replace ` + "`" + `yaml.YAMLError` + "`" + ` exception handling with ` + "`" + `err != nil` + "`" + ` checks after ` + "`" + `Unmarshal` + "`" + ` / ` + "`" + `Marshal` + "`" + `.
`,
		},
	)
}
