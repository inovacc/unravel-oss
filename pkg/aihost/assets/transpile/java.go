/*
Copyright (c) 2026 Security Research
*/
package transpile

import "github.com/inovacc/unravel-oss/pkg/aihost"

func init() {
	aihost.RegisterAsset(
		aihost.Asset{
			Path: "skills/transpile/rules/java/commons_io.md",
			Body: `## Apache Commons IO to Go Conversion Rules

- Map ` + "`" + `FileUtils.readFileToString()` + "`" + ` to ` + "`" + `os.ReadFile()` + "`" + `.
- Convert ` + "`" + `FileUtils.writeStringToFile()` + "`" + ` to ` + "`" + `os.WriteFile()` + "`" + `.
- Replace ` + "`" + `FileUtils.copyFile()` + "`" + ` with ` + "`" + `io.Copy()` + "`" + ` between files.
- Map ` + "`" + `FileUtils.deleteDirectory()` + "`" + ` to ` + "`" + `os.RemoveAll()` + "`" + `.
- Convert ` + "`" + `IOUtils.toString(inputStream)` + "`" + ` to ` + "`" + `io.ReadAll()` + "`" + `.
- Replace ` + "`" + `IOUtils.copy()` + "`" + ` with ` + "`" + `io.Copy()` + "`" + `.
- Map ` + "`" + `FileUtils.listFiles()` + "`" + ` to ` + "`" + `filepath.WalkDir()` + "`" + ` or ` + "`" + `os.ReadDir()` + "`" + `.
- Convert ` + "`" + `FilenameUtils.getExtension()` + "`" + ` to ` + "`" + `filepath.Ext()` + "`" + `.
- Replace ` + "`" + `FilenameUtils.getBaseName()` + "`" + ` with ` + "`" + `filepath.Base()` + "`" + ` + ` + "`" + `strings.TrimSuffix()` + "`" + `.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/java/commons_lang.md",
			Body: `## Apache Commons Lang to Go Conversion Rules

- Map ` + "`" + `StringUtils.isEmpty()` + "`" + ` / ` + "`" + `isBlank()` + "`" + ` to ` + "`" + `s == ""` + "`" + ` / ` + "`" + `strings.TrimSpace(s) == ""` + "`" + `.
- Convert ` + "`" + `StringUtils.join()` + "`" + ` to ` + "`" + `strings.Join()` + "`" + `.
- Replace ` + "`" + `StringUtils.capitalize()` + "`" + ` with ` + "`" + `strings.ToUpper(s[:1]) + s[1:]` + "`" + `.
- Map ` + "`" + `StringUtils.substringBefore/After()` + "`" + ` to ` + "`" + `strings.Cut()` + "`" + ` or index-based slicing.
- Convert ` + "`" + `RandomStringUtils` + "`" + ` to ` + "`" + `crypto/rand` + "`" + ` based generation.
- Replace ` + "`" + `NumberUtils.toInt()` + "`" + ` with ` + "`" + `strconv.Atoi()` + "`" + `.
- Map ` + "`" + `ArrayUtils` + "`" + ` operations to slice operations.
- Convert ` + "`" + `ObjectUtils.defaultIfNull()` + "`" + ` to nil check with default value.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/java/ear_structure.md",
			Body: `## EAR Structure to Go Conversion Rules

- Map each EAR module (web, ejb, java) to a separate Go package under internal/.
- Convert WAR modules to HTTP server packages with chi router.
- Convert EJB modules to service packages with business logic.
- Map Java utility modules to shared internal packages.
- Convert application.xml module declarations to Go package organization.
- Map context-root entries to URL prefix configurations.
- Replace shared libraries (lib/) with Go module dependencies.
- Convert security-role declarations to role constants and authorization middleware.
- Map inter-module communication (EJB remote) to internal function calls or gRPC.
- Replace connector modules with database/queue client packages.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/java/ejb.md",
			Body: `## Enterprise JavaBeans (EJB) to Go Conversion Rules

- Map ` + "`" + `@Stateless` + "`" + ` session bean to a stateless service struct with methods.
- Map ` + "`" + `@Stateful` + "`" + ` session bean to a struct with state fields and a constructor.
- Map ` + "`" + `@Singleton` + "`" + ` bean to package-level var + ` + "`" + `sync.Once` + "`" + ` initialization.
- Convert ` + "`" + `@MessageDriven` + "`" + ` bean to a consumer goroutine reading from a channel or message queue.
- Map ` + "`" + `@Schedule` + "`" + ` / ` + "`" + `@Timeout` + "`" + ` to ` + "`" + `time.Ticker` + "`" + ` or a cron scheduling library.
- Replace ` + "`" + `@EJB` + "`" + ` injection with constructor parameter injection.
- Convert ` + "`" + `@TransactionAttribute(REQUIRED)` + "`" + ` to explicit ` + "`" + `tx, err := db.BeginTx(ctx, nil)` + "`" + ` with ` + "`" + `defer tx.Rollback()` + "`" + `.
- Map ` + "`" + `@PostConstruct` + "`" + ` to initialization in the constructor (` + "`" + `NewX()` + "`" + ` factory function).
- Map ` + "`" + `@PreDestroy` + "`" + ` to a ` + "`" + `Close()` + "`" + ` method called via ` + "`" + `defer` + "`" + `.
- Replace remote EJB calls with gRPC or HTTP client calls.
- Convert ` + "`" + `SessionContext` + "`" + ` to ` + "`" + `context.Context` + "`" + `.
- Map entity manager injection to repository struct with ` + "`" + `*sql.DB` + "`" + ` dependency.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/java/gson.md",
			Body: `## Gson to Go Conversion Rules

- Map ` + "`" + `Gson.toJson()` + "`" + ` to ` + "`" + `json.Marshal()` + "`" + `.
- Convert ` + "`" + `Gson.fromJson()` + "`" + ` to ` + "`" + `json.Unmarshal()` + "`" + `.
- Replace ` + "`" + `@SerializedName("name")` + "`" + ` with struct tag ` + "`" + `json:"name"` + "`" + `.
- Map ` + "`" + `@Expose` + "`" + ` to ` + "`" + `json:"-"` + "`" + ` for excluded fields.
- Convert ` + "`" + `TypeAdapter<T>` + "`" + ` to ` + "`" + `json.Marshaler` + "`" + `/` + "`" + `json.Unmarshaler` + "`" + ` interface.
- Replace ` + "`" + `JsonElement` + "`" + `/` + "`" + `JsonObject` + "`" + `/` + "`" + `JsonArray` + "`" + ` with ` + "`" + `map[string]any` + "`" + `/` + "`" + `[]any` + "`" + `.
- Map ` + "`" + `GsonBuilder` + "`" + ` configuration to ` + "`" + `json.Encoder` + "`" + `/` + "`" + `json.Decoder` + "`" + ` options.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/java/guava.md",
			Body: `## Guava to Go Conversion Rules

- Map ` + "`" + `ImmutableList.of()` + "`" + ` to Go slice literal (slices are value-copied on assignment if needed).
- Convert ` + "`" + `ImmutableMap.of()` + "`" + ` to Go map literal.
- Replace ` + "`" + `Optional<T>` + "`" + ` to ` + "`" + `*T` + "`" + ` (nil = absent).
- Map ` + "`" + `Preconditions.checkNotNull()` + "`" + ` to explicit ` + "`" + `if x == nil { panic/return error }` + "`" + `.
- Convert ` + "`" + `Preconditions.checkArgument()` + "`" + ` to ` + "`" + `if !cond { return fmt.Errorf(...) }` + "`" + `.
- Replace ` + "`" + `Strings.isNullOrEmpty()` + "`" + ` with ` + "`" + `s == ""` + "`" + ` check.
- Map ` + "`" + `Lists.newArrayList()` + "`" + ` to ` + "`" + `make([]T, 0)` + "`" + ` or ` + "`" + `[]T{}` + "`" + `.
- Convert ` + "`" + `Maps.newHashMap()` + "`" + ` to ` + "`" + `make(map[K]V)` + "`" + `.
- Replace ` + "`" + `Joiner` + "`" + `/` + "`" + `Splitter` + "`" + ` with ` + "`" + `strings.Join()` + "`" + `/` + "`" + `strings.Split()` + "`" + `.
- Map ` + "`" + `Cache` + "`" + `/` + "`" + `LoadingCache` + "`" + ` to ` + "`" + `sync.Map` + "`" + ` or custom cache with ` + "`" + `sync.RWMutex` + "`" + `.
- Convert ` + "`" + `ListenableFuture` + "`" + ` to goroutine + channel.
- Replace ` + "`" + `EventBus` + "`" + ` with channels or observer pattern.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/java/hibernate.md",
			Body: `## Hibernate to Go Conversion Rules

- Map ` + "`" + `@Entity` + "`" + ` classes to Go structs with database tags.
- Convert ` + "`" + `SessionFactory` + "`" + `/` + "`" + `Session` + "`" + ` to ` + "`" + `*sql.DB` + "`" + ` and ` + "`" + `*sql.Tx` + "`" + `.
- Replace ` + "`" + `session.save()` + "`" + `/` + "`" + `session.update()` + "`" + ` with ` + "`" + `db.Exec()` + "`" + ` INSERT/UPDATE queries.
- Map ` + "`" + `@Query` + "`" + ` (HQL/JPQL) to sqlc-generated Go queries.
- Convert ` + "`" + `CriteriaBuilder` + "`" + ` queries to raw SQL or query builder.
- Replace ` + "`" + `@OneToMany` + "`" + `/` + "`" + `@ManyToOne` + "`" + ` relationships with explicit JOIN queries.
- Map ` + "`" + `@Transactional` + "`" + ` to ` + "`" + `tx.Begin()` + "`" + `/` + "`" + `tx.Commit()` + "`" + `/` + "`" + `tx.Rollback()` + "`" + `.
- Convert ` + "`" + `@Cacheable` + "`" + ` entity caching to application-level cache.
- Replace Hibernate lazy loading with explicit query strategies.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/java/jackson.md",
			Body: `## Jackson to Go Conversion Rules

- Map ` + "`" + `@JsonProperty("name")` + "`" + ` to struct tag ` + "`" + `json:"name"` + "`" + `.
- Convert ` + "`" + `ObjectMapper.writeValueAsString()` + "`" + ` to ` + "`" + `json.Marshal()` + "`" + `.
- Replace ` + "`" + `ObjectMapper.readValue()` + "`" + ` with ` + "`" + `json.Unmarshal()` + "`" + `.
- Map ` + "`" + `@JsonIgnore` + "`" + ` to struct tag ` + "`" + `json:"-"` + "`" + `.
- Convert ` + "`" + `@JsonInclude(NON_NULL)` + "`" + ` to ` + "`" + `json:"name,omitempty"` + "`" + `.
- Replace ` + "`" + `@JsonCreator` + "`" + `/` + "`" + `@JsonValue` + "`" + ` with custom ` + "`" + `json.Marshaler` + "`" + `/` + "`" + `json.Unmarshaler` + "`" + `.
- Map ` + "`" + `@JsonFormat` + "`" + ` date patterns to custom ` + "`" + `time.Time` + "`" + ` marshal/unmarshal.
- Convert ` + "`" + `@JsonTypeInfo` + "`" + `/` + "`" + `@JsonSubTypes` + "`" + ` to interface + concrete type unmarshaling.
- Replace ` + "`" + `JsonNode` + "`" + ` tree model with ` + "`" + `json.RawMessage` + "`" + ` or ` + "`" + `map[string]any` + "`" + `.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/java/javaee.md",
			Body: `## Java EE / Jakarta EE to Go Conversion Rules

- Map ` + "`" + `javax.servlet.*` + "`" + ` / ` + "`" + `jakarta.servlet.*` + "`" + ` to ` + "`" + `net/http` + "`" + ` handlers and middleware.
- Convert ` + "`" + `javax.inject.Inject` + "`" + ` / ` + "`" + `jakarta.inject.Inject` + "`" + ` to constructor parameter injection.
- Map ` + "`" + `javax.ws.rs.*` + "`" + ` (JAX-RS) to chi router handlers:
  - ` + "`" + `@Path` + "`" + ` → chi route pattern
  - ` + "`" + `@GET/@POST/@PUT/@DELETE` + "`" + ` → ` + "`" + `r.Get/r.Post/r.Put/r.Delete` + "`" + `
  - ` + "`" + `@PathParam` + "`" + ` → ` + "`" + `chi.URLParam(r, "name")` + "`" + `
  - ` + "`" + `@QueryParam` + "`" + ` → ` + "`" + `r.URL.Query().Get("name")` + "`" + `
  - ` + "`" + `@Produces("application/json")` + "`" + ` → ` + "`" + `w.Header().Set("Content-Type", "application/json")` + "`" + `
  - ` + "`" + `@Consumes` + "`" + ` → content type validation middleware
- Convert ` + "`" + `javax.transaction.*` + "`" + ` / ` + "`" + `jakarta.transaction.*` + "`" + ` to ` + "`" + `database/sql` + "`" + ` transactions:
  - ` + "`" + `@Transactional` + "`" + ` → explicit ` + "`" + `tx, err := db.BeginTx(ctx, nil)` + "`" + ` with defer rollback
  - ` + "`" + `UserTransaction` + "`" + ` → ` + "`" + `*sql.Tx` + "`" + `
- Map ` + "`" + `javax.validation.*` + "`" + ` / ` + "`" + `jakarta.validation.*` + "`" + ` to struct tags + validator library.
- Replace ` + "`" + `javax.enterprise.event.*` + "`" + ` (CDI events) with channels or observer pattern.
- Convert ` + "`" + `javax.json.*` + "`" + ` to ` + "`" + `encoding/json` + "`" + `.
- Map ` + "`" + `javax.websocket.*` + "`" + ` to ` + "`" + `gorilla/websocket` + "`" + ` or ` + "`" + `nhooyr.io/websocket` + "`" + `.
- Replace ` + "`" + `javax.mail.*` + "`" + ` with ` + "`" + `net/smtp` + "`" + ` or a mail library.
- Convert ` + "`" + `javax.security.*` + "`" + ` to middleware-based authentication/authorization.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/java/jndi.md",
			Body: `## JNDI to Go Conversion Rules

- Replace ` + "`" + `InitialContext.lookup("java:comp/env/...")` + "`" + ` with direct config struct injection.
- Convert ` + "`" + `@Resource(name = "...")` + "`" + ` to constructor parameter or config field.
- Map JNDI DataSource lookups to ` + "`" + `*sql.DB` + "`" + ` passed via constructor.
- Replace ` + "`" + `Context.lookup()` + "`" + ` for JMS with direct message queue client injection.
- Convert environment entries (` + "`" + `java:comp/env/` + "`" + `) to ` + "`" + `os.Getenv()` + "`" + ` or config struct fields.
- Map JNDI-based service locator pattern to dependency injection via constructors.
- Replace ` + "`" + `java:global/` + "`" + ` lookups with package imports and direct function calls.
- Convert ` + "`" + `@Resource` + "`" + ` for connection factories to constructor-injected client instances.
- Replace LDAP JNDI lookups with a dedicated LDAP client library (e.g., go-ldap).
- Map all JNDI naming to flat configuration: environment variables or config files.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/java/jpa.md",
			Body: `## JPA to Go Conversion Rules

- Map ` + "`" + `@Entity` + "`" + ` to Go struct with db struct tags.
- Convert ` + "`" + `@Column(name="col")` + "`" + ` to struct tag ` + "`" + `db:"col"` + "`" + `.
- Replace ` + "`" + `@Id` + "`" + `/` + "`" + `@GeneratedValue` + "`" + ` with explicit primary key handling.
- Map ` + "`" + `CrudRepository<T, ID>` + "`" + ` interface to sqlc-generated query functions.
- Convert ` + "`" + `JpaRepository` + "`" + ` ` + "`" + `findBy*` + "`" + ` methods to SQL queries via sqlc.
- Replace ` + "`" + `@Query("SELECT ...")` + "`" + ` with sqlc query definitions.
- Map ` + "`" + `EntityManager.persist()` + "`" + `/` + "`" + `merge()` + "`" + ` to INSERT/UPDATE with sqlc.
- Convert ` + "`" + `Pageable` + "`" + `/` + "`" + `Page<T>` + "`" + ` to LIMIT/OFFSET queries.
- Replace ` + "`" + `@Enumerated` + "`" + ` with Go const + custom scanner/valuer.
- Map ` + "`" + `@Embedded` + "`" + `/` + "`" + `@Embeddable` + "`" + ` to embedded structs.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/java/junit.md",
			Body: `## JUnit 5 to Go Conversion Rules

- Replace ` + "`" + `@Test` + "`" + ` methods with ` + "`" + `func TestMethodName(t *testing.T)` + "`" + `.
- Map ` + "`" + `@BeforeEach` + "`" + `/` + "`" + `@AfterEach` + "`" + ` to test helper setup/teardown called at start/end of each test.
- Convert ` + "`" + `@BeforeAll` + "`" + `/` + "`" + `@AfterAll` + "`" + ` to ` + "`" + `TestMain(m *testing.M)` + "`" + `.
- Replace ` + "`" + `Assertions.assertEquals(expected, actual)` + "`" + ` with ` + "`" + `assert.Equal(t, expected, actual)` + "`" + ` or ` + "`" + `if got != want { t.Errorf(...) }` + "`" + `.
- Map ` + "`" + `Assertions.assertThrows` + "`" + ` to checking ` + "`" + `err != nil` + "`" + ` with ` + "`" + `errors.Is` + "`" + `/` + "`" + `errors.As` + "`" + `.
- Convert ` + "`" + `@ParameterizedTest` + "`" + ` + ` + "`" + `@ValueSource` + "`" + `/` + "`" + `@CsvSource` + "`" + ` to table-driven tests.
- Replace ` + "`" + `@Disabled` + "`" + ` with ` + "`" + `t.Skip()` + "`" + `.
- Map ` + "`" + `@DisplayName` + "`" + ` to test function documentation comments.
- Convert ` + "`" + `@Nested` + "`" + ` test classes to subtests with ` + "`" + `t.Run()` + "`" + `.
- Replace ` + "`" + `@Timeout` + "`" + ` with ` + "`" + `context.WithTimeout` + "`" + ` in tests.
- Map ` + "`" + `assertAll()` + "`" + ` to multiple assertion checks.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/java/kafka.md",
			Body: `## Apache Kafka to Go Conversion Rules

- Map ` + "`" + `KafkaConsumer<K,V>` + "`" + ` to ` + "`" + `kafka-go` + "`" + ` ` + "`" + `Reader` + "`" + `.
- Convert ` + "`" + `KafkaProducer<K,V>` + "`" + ` to ` + "`" + `kafka-go` + "`" + ` ` + "`" + `Writer` + "`" + `.
- Replace ` + "`" + `ConsumerRecord<K,V>` + "`" + ` with ` + "`" + `kafka.Message` + "`" + `.
- Map ` + "`" + `@KafkaListener` + "`" + ` to goroutine running ` + "`" + `reader.ReadMessage()` + "`" + ` loop.
- Convert ` + "`" + `ProducerRecord<K,V>` + "`" + ` to ` + "`" + `kafka.Message` + "`" + ` struct.
- Replace ` + "`" + `ConsumerConfig` + "`" + ` / ` + "`" + `ProducerConfig` + "`" + ` to ` + "`" + `kafka.ReaderConfig` + "`" + ` / ` + "`" + `kafka.WriterConfig` + "`" + `.
- Map ` + "`" + `KafkaTemplate.send()` + "`" + ` to ` + "`" + `writer.WriteMessages()` + "`" + `.
- Convert Kafka Streams to custom goroutine pipeline with channels.
- Replace ` + "`" + `Serde` + "`" + ` serialization with ` + "`" + `json.Marshal` + "`" + `/` + "`" + `json.Unmarshal` + "`" + ` or protobuf.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/java/log4j.md",
			Body: `## Log4j 2 to Go Conversion Rules

- Map ` + "`" + `LogManager.getLogger(Class)` + "`" + ` to ` + "`" + `slog.New()` + "`" + ` or package-level ` + "`" + `slog.Logger` + "`" + `.
- Convert ` + "`" + `logger.info("message")` + "`" + ` to ` + "`" + `slog.Info("message")` + "`" + `.
- Replace ` + "`" + `logger.error("message", exception)` + "`" + ` with ` + "`" + `slog.Error("message", "error", err)` + "`" + `.
- Map ` + "`" + `logger.debug()` + "`" + ` to ` + "`" + `slog.Debug()` + "`" + `.
- Convert ` + "`" + `logger.warn()` + "`" + ` to ` + "`" + `slog.Warn()` + "`" + `.
- Replace Log4j XML/properties configuration with programmatic ` + "`" + `slog.Handler` + "`" + ` setup.
- Map ` + "`" + `Appender` + "`" + ` to ` + "`" + `slog.Handler` + "`" + ` (JSON handler, text handler, etc.).
- Convert ` + "`" + `PatternLayout` + "`" + ` formatting to slog handler options.
- Replace ` + "`" + `Marker` + "`" + ` with slog attribute groups.
- Map ` + "`" + `ThreadContext` + "`" + ` (MDC) to ` + "`" + `slog.With()` + "`" + ` or context values.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/java/lombok.md",
			Body: `## Lombok to Go Conversion Rules

- Replace ` + "`" + `@Data` + "`" + ` with explicit Go struct (public fields, Go has no getter/setter convention).
- Convert ` + "`" + `@Builder` + "`" + ` to functional options pattern or builder struct.
- Map ` + "`" + `@Slf4j` + "`" + `/` + "`" + `@Log4j2` + "`" + ` to ` + "`" + `slog.Logger` + "`" + ` field or package-level logger.
- Replace ` + "`" + `@Getter` + "`" + `/` + "`" + `@Setter` + "`" + ` — Go uses public fields directly (PascalCase).
- Convert ` + "`" + `@NoArgsConstructor` + "`" + `/` + "`" + `@AllArgsConstructor` + "`" + ` to ` + "`" + `NewX()` + "`" + ` factory functions.
- Map ` + "`" + `@ToString` + "`" + ` to ` + "`" + `String() string` + "`" + ` method.
- Replace ` + "`" + `@EqualsAndHashCode` + "`" + ` with custom ` + "`" + `Equal()` + "`" + ` method if needed.
- Convert ` + "`" + `@Value` + "`" + ` (immutable) to struct with unexported fields + getters.
- Map ` + "`" + `@With` + "`" + ` to functional copy methods.
- Replace ` + "`" + `@RequiredArgsConstructor` + "`" + ` with constructor taking required fields.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/java/mockito.md",
			Body: `## Mockito to Go Conversion Rules

- Replace ` + "`" + `@Mock` + "`" + ` annotations with interface + hand-written mock struct.
- Convert ` + "`" + `when(mock.method()).thenReturn(value)` + "`" + ` to mock struct field/method setup.
- Map ` + "`" + `verify(mock).method()` + "`" + ` to assertion on mock call count.
- Replace ` + "`" + `@InjectMocks` + "`" + ` with explicit constructor injection in test.
- Convert ` + "`" + `ArgumentCaptor` + "`" + ` to mock method recording calls.
- Map ` + "`" + `doThrow()` + "`" + `/` + "`" + `doNothing()` + "`" + ` to mock method returning error or nil.
- Replace ` + "`" + `@Spy` + "`" + ` with partial mock (embed real struct, override specific methods).
- Convert ` + "`" + `Mockito.mockStatic()` + "`" + ` to interface wrapping + DI.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/java/netty.md",
			Body: `## Netty to Go Conversion Rules

- Map ` + "`" + `Channel` + "`" + ` to ` + "`" + `net.Conn` + "`" + `.
- Convert ` + "`" + `EventLoopGroup` + "`" + ` / ` + "`" + `NioEventLoopGroup` + "`" + ` to goroutine pool.
- Replace ` + "`" + `ChannelHandler` + "`" + ` / ` + "`" + `ChannelInboundHandlerAdapter` + "`" + ` with handler function.
- Map ` + "`" + `ByteBuf` + "`" + ` to ` + "`" + `[]byte` + "`" + ` or ` + "`" + `bytes.Buffer` + "`" + `.
- Convert ` + "`" + `ChannelPipeline` + "`" + ` to middleware chain.
- Replace ` + "`" + `Bootstrap` + "`" + ` / ` + "`" + `ServerBootstrap` + "`" + ` to ` + "`" + `net.Listen()` + "`" + ` + accept loop.
- Map ` + "`" + `ChannelFuture` + "`" + ` to goroutine + channel.
- Convert Netty codecs (encoder/decoder) to custom ` + "`" + `io.Reader` + "`" + `/` + "`" + `io.Writer` + "`" + ` wrappers.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/java/okhttp.md",
			Body: `## OkHttp to Go Conversion Rules

- Map ` + "`" + `OkHttpClient` + "`" + ` to ` + "`" + `http.Client` + "`" + `.
- Convert ` + "`" + `Request.Builder` + "`" + ` to ` + "`" + `http.NewRequest()` + "`" + `.
- Replace ` + "`" + `Response.body().string()` + "`" + ` with ` + "`" + `io.ReadAll(resp.Body)` + "`" + `.
- Map ` + "`" + `MediaType.parse("application/json")` + "`" + ` to ` + "`" + `w.Header().Set("Content-Type", "application/json")` + "`" + `.
- Convert ` + "`" + `RequestBody.create()` + "`" + ` to ` + "`" + `bytes.NewReader()` + "`" + ` or ` + "`" + `strings.NewReader()` + "`" + `.
- Replace ` + "`" + `Interceptor` + "`" + ` with ` + "`" + `http.RoundTripper` + "`" + ` wrapper.
- Map ` + "`" + `WebSocket` + "`" + ` to ` + "`" + `nhooyr.io/websocket` + "`" + ` or ` + "`" + `gorilla/websocket` + "`" + `.
- Convert ` + "`" + `ConnectionPool` + "`" + ` to ` + "`" + `http.Transport` + "`" + ` connection settings.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/java/retrofit.md",
			Body: `## Retrofit to Go Conversion Rules

- Map ` + "`" + `@GET("path")` + "`" + ` interface methods to ` + "`" + `http.NewRequest("GET", url, nil)` + "`" + `.
- Convert ` + "`" + `@POST("path")` + "`" + ` to ` + "`" + `http.NewRequest("POST", url, body)` + "`" + `.
- Replace ` + "`" + `@Path("name")` + "`" + ` with URL string formatting.
- Map ` + "`" + `@Query("name")` + "`" + ` to URL query parameter addition.
- Convert ` + "`" + `@Body` + "`" + ` to ` + "`" + `json.Marshal()` + "`" + ` + request body.
- Replace ` + "`" + `Call<T>` + "`" + ` return type with ` + "`" + `(T, error)` + "`" + `.
- Map Retrofit ` + "`" + `Callback<T>` + "`" + ` to goroutine + channel or direct call.
- Convert ` + "`" + `OkHttpClient` + "`" + ` interceptors to ` + "`" + `http.RoundTripper` + "`" + ` middleware.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/java/rxjava.md",
			Body: `## RxJava to Go Conversion Rules

- Map ` + "`" + `Observable<T>` + "`" + ` to ` + "`" + `chan T` + "`" + ` or iterator pattern.
- Convert ` + "`" + `Observable.just()` + "`" + ` to direct channel send or function return.
- Replace ` + "`" + `Observable.map()` + "`" + ` with explicit for loop transformation.
- Map ` + "`" + `Observable.filter()` + "`" + ` to for loop with condition.
- Convert ` + "`" + `Observable.flatMap()` + "`" + ` to goroutine fan-out + merge.
- Replace ` + "`" + `Schedulers.io()` + "`" + ` / ` + "`" + `Schedulers.computation()` + "`" + ` with goroutines.
- Map ` + "`" + `Flowable<T>` + "`" + ` (backpressure) to buffered channel.
- Convert ` + "`" + `Disposable` + "`" + ` to ` + "`" + `context.CancelFunc` + "`" + `.
- Replace ` + "`" + `PublishSubject` + "`" + ` / ` + "`" + `BehaviorSubject` + "`" + ` with channel broadcasting.
- Map ` + "`" + `Single<T>` + "`" + ` to ` + "`" + `func() (T, error)` + "`" + ` or channel with single value.
- Convert ` + "`" + `Completable` + "`" + ` to ` + "`" + `func() error` + "`" + `.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/java/servlet.md",
			Body: `## Java Servlet API to Go Conversion Rules

- Map ` + "`" + `HttpServlet.doGet()` + "`" + ` / ` + "`" + `doPost()` + "`" + ` / ` + "`" + `doPut()` + "`" + ` / ` + "`" + `doDelete()` + "`" + ` to ` + "`" + `http.HandlerFunc` + "`" + ` or chi handler functions.
- Convert ` + "`" + `HttpServletRequest` + "`" + ` to ` + "`" + `*http.Request` + "`" + ` and ` + "`" + `HttpServletResponse` + "`" + ` to ` + "`" + `http.ResponseWriter` + "`" + `.
- Map ` + "`" + `Filter.doFilter()` + "`" + ` to middleware function ` + "`" + `func(next http.Handler) http.Handler` + "`" + `.
- Convert ` + "`" + `FilterChain.doFilter()` + "`" + ` to ` + "`" + `next.ServeHTTP(w, r)` + "`" + `.
- Replace ` + "`" + `HttpSession` + "`" + ` with a session library (e.g., gorilla/sessions) or cookie-based state.
- Convert ` + "`" + `ServletContext.getAttribute/setAttribute` + "`" + ` to package-level state or context values.
- Map ` + "`" + `@WebServlet(urlPatterns = "/path")` + "`" + ` to chi ` + "`" + `r.HandleFunc("/path", handler)` + "`" + `.
- Map ` + "`" + `@WebFilter(urlPatterns = "/*")` + "`" + ` to chi middleware ` + "`" + `r.Use(middleware)` + "`" + `.
- Convert ` + "`" + `ServletContextListener.contextInitialized` + "`" + ` to ` + "`" + `main()` + "`" + ` or ` + "`" + `init()` + "`" + ` setup.
- Replace ` + "`" + `RequestDispatcher.forward/include` + "`" + ` with internal handler calls or HTTP redirects.
- Map ` + "`" + `getParameter()` + "`" + ` to ` + "`" + `r.URL.Query().Get()` + "`" + ` or ` + "`" + `r.FormValue()` + "`" + `.
- Convert ` + "`" + `getInputStream()` + "`" + ` / ` + "`" + `getReader()` + "`" + ` to ` + "`" + `r.Body` + "`" + `.
- Map ` + "`" + `getWriter()` + "`" + ` / ` + "`" + `getOutputStream()` + "`" + ` to ` + "`" + `w.Write()` + "`" + ` or ` + "`" + `w` + "`" + ` (http.ResponseWriter).
- Replace ` + "`" + `sendRedirect()` + "`" + ` with ` + "`" + `http.Redirect(w, r, url, http.StatusFound)` + "`" + `.
- Convert ` + "`" + `setContentType()` + "`" + ` to ` + "`" + `w.Header().Set("Content-Type", ...)` + "`" + `.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/java/slf4j.md",
			Body: `## SLF4J to Go Conversion Rules

- Map ` + "`" + `Logger logger = LoggerFactory.getLogger(Class)` + "`" + ` to ` + "`" + `slog.Logger` + "`" + ` initialization.
- Convert ` + "`" + `logger.info("msg", arg)` + "`" + ` to ` + "`" + `slog.Info("msg", "key", arg)` + "`" + `.
- Replace ` + "`" + `logger.error("msg", exception)` + "`" + ` with ` + "`" + `slog.Error("msg", "error", err)` + "`" + `.
- Map ` + "`" + `logger.debug()` + "`" + ` to ` + "`" + `slog.Debug()` + "`" + `.
- Convert ` + "`" + `logger.warn()` + "`" + ` to ` + "`" + `slog.Warn()` + "`" + `.
- Replace MDC (Mapped Diagnostic Context) with ` + "`" + `slog.With()` + "`" + ` or ` + "`" + `context.WithValue` + "`" + `.
- Map SLF4J parameterized messages ` + "`" + `{}` + "`" + ` to slog key-value pairs.
- Convert Logback XML configuration to programmatic ` + "`" + `slog.Handler` + "`" + ` setup.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/java/spring.md",
			Body: `## Spring Framework to Go Conversion Rules

- Map ` + "`" + `@RestController` + "`" + ` + ` + "`" + `@RequestMapping` + "`" + ` to chi router handler functions.
- Convert ` + "`" + `@Autowired` + "`" + ` / ` + "`" + `@Inject` + "`" + ` dependencies to constructor parameters.
- Replace ` + "`" + `@GetMapping` + "`" + `/` + "`" + `@PostMapping` + "`" + `/etc. with chi ` + "`" + `r.Get` + "`" + `/` + "`" + `r.Post` + "`" + `/etc. registrations.
- Map ` + "`" + `@PathVariable` + "`" + ` to chi ` + "`" + `chi.URLParam(r, "name")` + "`" + `.
- Convert ` + "`" + `@RequestBody` + "`" + ` to ` + "`" + `json.NewDecoder(r.Body).Decode(&v)` + "`" + `.
- Map ` + "`" + `@RequestParam` + "`" + ` to ` + "`" + `r.URL.Query().Get("name")` + "`" + `.
- Replace ` + "`" + `ResponseEntity<T>` + "`" + ` with ` + "`" + `(T, error)` + "`" + ` return + ` + "`" + `json.NewEncoder(w).Encode()` + "`" + `.
- Convert ` + "`" + `@ExceptionHandler` + "`" + ` to middleware error handling.
- Map ` + "`" + `@Service` + "`" + `/` + "`" + `@Repository` + "`" + `/` + "`" + `@Component` + "`" + ` to plain struct constructors (no DI framework).
- Replace ` + "`" + `@Configuration` + "`" + `/` + "`" + `@Bean` + "`" + ` with constructor functions or ` + "`" + `sync.Once` + "`" + ` initialization.
- Convert ` + "`" + `@Transactional` + "`" + ` to explicit ` + "`" + `tx, err := db.Begin()` + "`" + ` with ` + "`" + `defer tx.Rollback()` + "`" + `.
- Map ` + "`" + `@Value("${prop}")` + "`" + ` to environment variable reads (` + "`" + `os.Getenv` + "`" + `).
- Replace ` + "`" + `@Scheduled` + "`" + ` with ` + "`" + `time.Ticker` + "`" + ` or ` + "`" + `cron` + "`" + ` library.
- Convert ` + "`" + `@Async` + "`" + ` methods to goroutine invocations.
- Map Spring Security ` + "`" + `@PreAuthorize` + "`" + ` to middleware authorization checks.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/java/testng.md",
			Body: `## TestNG to Go Conversion Rules

- Replace ` + "`" + `@Test` + "`" + ` methods with ` + "`" + `func TestMethodName(t *testing.T)` + "`" + `.
- Map ` + "`" + `@BeforeMethod` + "`" + `/` + "`" + `@AfterMethod` + "`" + ` to test helper setup/teardown.
- Convert ` + "`" + `@BeforeClass` + "`" + `/` + "`" + `@AfterClass` + "`" + ` to ` + "`" + `TestMain(m *testing.M)` + "`" + `.
- Replace ` + "`" + `@DataProvider` + "`" + ` with table-driven tests using ` + "`" + `[]struct{ ... }` + "`" + `.
- Map ` + "`" + `Assert.assertEquals()` + "`" + ` to ` + "`" + `assert.Equal(t, expected, actual)` + "`" + `.
- Convert ` + "`" + `@Test(expectedExceptions)` + "`" + ` to ` + "`" + `err != nil` + "`" + ` + ` + "`" + `errors.Is` + "`" + `/` + "`" + `errors.As` + "`" + `.
- Replace ` + "`" + `@Test(groups = ...)` + "`" + ` with build tags or subtests.
- Map ` + "`" + `@Listeners` + "`" + ` to test helper middleware.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/java/vertx.md",
			Body: `## Vert.x to Go Conversion Rules

- Map ` + "`" + `Verticle` + "`" + ` to goroutine.
- Convert ` + "`" + `EventBus` + "`" + ` to Go channels.
- Replace ` + "`" + `Vertx.createHttpServer()` + "`" + ` with ` + "`" + `http.ListenAndServe()` + "`" + `.
- Map ` + "`" + `Router` + "`" + ` to chi router.
- Convert ` + "`" + `Future<T>` + "`" + ` / ` + "`" + `Promise<T>` + "`" + ` to goroutine + channel.
- Replace ` + "`" + `Handler<AsyncResult<T>>` + "`" + ` with callback function ` + "`" + `func(T, error)` + "`" + `.
- Map ` + "`" + `JsonObject` + "`" + ` / ` + "`" + `JsonArray` + "`" + ` to ` + "`" + `map[string]any` + "`" + ` / ` + "`" + `[]any` + "`" + `.
- Convert ` + "`" + `vertx.executeBlocking()` + "`" + ` to goroutine.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/java/war_structure.md",
			Body: `## WAR Structure to Go Conversion Rules

- Map web.xml servlet declarations to chi router ` + "`" + `r.HandleFunc()` + "`" + ` registrations.
- Convert web.xml filter chains to chi middleware stack via ` + "`" + `r.Use()` + "`" + `.
- Map servlet-mapping URL patterns to chi route patterns.
- Convert filter-mapping to middleware applied to route groups.
- Map welcome-file-list to a default route serving static files.
- Convert error-page declarations to custom error handler middleware.
- Map context-param entries to configuration values loaded at startup.
- Replace WEB-INF/classes with Go packages in internal/.
- Replace WEB-INF/lib JARs with Go module dependencies in go.mod.
- Convert security-constraint with auth-constraint to authentication middleware.
- Map session-config timeout to session middleware configuration.
- Convert listener declarations to init() setup or main() startup hooks.
`,
		},
	)
}
