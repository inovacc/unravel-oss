/**
 * Test Scenario 04: Async Batch Processing System
 * Difficulty: Hard (~500 LOC)
 *
 * Tests:
 * - Generics with multiple type parameters
 * - Sealed interfaces with record variants (Java 17+)
 * - CompletableFuture composition (thenApply, thenCompose, allOf, exceptionally)
 * - ExecutorService and thread pool management
 * - Semaphore for rate limiting
 * - AtomicInteger for progress tracking
 * - Retry logic with exponential backoff
 * - Duration and Instant for timing
 * - Functional interfaces (Function, Predicate, Consumer)
 * - Pipeline pattern chaining stages
 * - ConcurrentHashMap for metrics collection
 * - Try-with-resources for executor shutdown
 *
 * Expected Go mappings:
 * - sealed interface          -> interface with unexported method marker
 * - record variants           -> structs implementing sealed interface
 * - CompletableFuture         -> goroutine + channel or errgroup
 * - ExecutorService           -> worker pool with goroutines
 * - Semaphore                 -> buffered channel (chan struct{})
 * - AtomicInteger             -> atomic.Int32
 * - Duration                  -> time.Duration
 * - Function<T,R>             -> func(T) R
 * - ConcurrentHashMap         -> sync.Map or map + sync.RWMutex
 * - try-with-resources        -> defer
 */

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;

public class AsyncProcessor {

    // --- Work Item ---

    public enum WorkStatus { PENDING, PROCESSING, COMPLETED, FAILED, TIMED_OUT }

    public static class WorkItem<T> {
        private final String id;
        private final T payload;
        private volatile WorkStatus status;
        private volatile Object result;
        private volatile Throwable error;
        private final Instant createdAt;

        public WorkItem(T payload) {
            this.id = UUID.randomUUID().toString().substring(0, 8);
            this.payload = payload;
            this.status = WorkStatus.PENDING;
            this.createdAt = Instant.now();
        }

        public String getId() { return id; }
        public T getPayload() { return payload; }
        public WorkStatus getStatus() { return status; }
        public Instant getCreatedAt() { return createdAt; }

        void setStatus(WorkStatus status) { this.status = status; }
        void setResult(Object result) { this.result = result; }
        void setError(Throwable error) { this.error = error; }

        @SuppressWarnings("unchecked")
        public <R> R getResult() { return (R) result; }
        public Throwable getError() { return error; }

        @Override
        public String toString() {
            return String.format("WorkItem{id=%s, status=%s, payload=%s}", id, status, payload);
        }
    }

    // --- Processing Result (Sealed Interface) ---

    public sealed interface ProcessingResult<T> permits
            ProcessingResult.Success, ProcessingResult.Failure, ProcessingResult.Timeout {

        String itemId();
        Duration duration();

        record Success<T>(String itemId, T value, Duration duration) implements ProcessingResult<T> {}
        record Failure<T>(String itemId, Throwable error, int attempts, Duration duration) implements ProcessingResult<T> {}
        record Timeout<T>(String itemId, Duration timeout, Duration duration) implements ProcessingResult<T> {}

        default boolean isSuccess() { return this instanceof Success; }
        default boolean isFailure() { return this instanceof Failure; }
        default boolean isTimeout() { return this instanceof Timeout; }

        default <R> R fold(
                Function<Success<T>, R> onSuccess,
                Function<Failure<T>, R> onFailure,
                Function<Timeout<T>, R> onTimeout
        ) {
            if (this instanceof Success<T> s) return onSuccess.apply(s);
            if (this instanceof Failure<T> f) return onFailure.apply(f);
            if (this instanceof Timeout<T> t) return onTimeout.apply(t);
            throw new IllegalStateException("Unhandled result type");
        }
    }

    // --- Metrics Collector ---

    public static class MetricsCollector {
        private final AtomicLong totalProcessed = new AtomicLong(0);
        private final AtomicLong totalSucceeded = new AtomicLong(0);
        private final AtomicLong totalFailed = new AtomicLong(0);
        private final AtomicLong totalTimedOut = new AtomicLong(0);
        private final AtomicLong totalRetries = new AtomicLong(0);
        private final ConcurrentHashMap<String, Long> processingTimes = new ConcurrentHashMap<>();
        private final Instant startedAt;

        public MetricsCollector() {
            this.startedAt = Instant.now();
        }

        public void recordSuccess(String itemId, Duration duration) {
            totalProcessed.incrementAndGet();
            totalSucceeded.incrementAndGet();
            processingTimes.put(itemId, duration.toMillis());
        }

        public void recordFailure(String itemId, Duration duration) {
            totalProcessed.incrementAndGet();
            totalFailed.incrementAndGet();
            processingTimes.put(itemId, duration.toMillis());
        }

        public void recordTimeout(String itemId) {
            totalProcessed.incrementAndGet();
            totalTimedOut.incrementAndGet();
        }

        public void recordRetry() {
            totalRetries.incrementAndGet();
        }

        public double getAverageProcessingTimeMs() {
            var times = processingTimes.values();
            if (times.isEmpty()) return 0;
            return times.stream().mapToLong(Long::longValue).average().orElse(0);
        }

        public long getMaxProcessingTimeMs() {
            return processingTimes.values().stream().mapToLong(Long::longValue).max().orElse(0);
        }

        public Duration getElapsed() {
            return Duration.between(startedAt, Instant.now());
        }

        public double getSuccessRate() {
            long total = totalProcessed.get();
            return total == 0 ? 0 : (double) totalSucceeded.get() / total * 100;
        }

        public String getSummary() {
            return String.format(
                    "Metrics{processed=%d, succeeded=%d, failed=%d, timedOut=%d, retries=%d, " +
                            "avgTime=%.1fms, maxTime=%dms, successRate=%.1f%%, elapsed=%s}",
                    totalProcessed.get(), totalSucceeded.get(), totalFailed.get(),
                    totalTimedOut.get(), totalRetries.get(),
                    getAverageProcessingTimeMs(), getMaxProcessingTimeMs(),
                    getSuccessRate(), getElapsed()
            );
        }
    }

    // --- Batch Processor ---

    public static class BatchProcessor<T, R> {
        private final Function<T, R> processingFunction;
        private final ExecutorService executor;
        private final Semaphore rateLimiter;
        private final Duration itemTimeout;
        private final int maxRetries;
        private final Duration baseRetryDelay;
        private final MetricsCollector metrics;
        private final AtomicInteger progress;
        private final Consumer<String> progressCallback;

        public BatchProcessor(
                Function<T, R> processingFunction,
                int threadPoolSize,
                int maxConcurrent,
                Duration itemTimeout,
                int maxRetries,
                Duration baseRetryDelay,
                Consumer<String> progressCallback
        ) {
            this.processingFunction = processingFunction;
            this.executor = Executors.newFixedThreadPool(threadPoolSize);
            this.rateLimiter = new Semaphore(maxConcurrent);
            this.itemTimeout = itemTimeout;
            this.maxRetries = maxRetries;
            this.baseRetryDelay = baseRetryDelay;
            this.metrics = new MetricsCollector();
            this.progress = new AtomicInteger(0);
            this.progressCallback = progressCallback;
        }

        public CompletableFuture<List<ProcessingResult<R>>> processBatch(List<T> items) {
            List<CompletableFuture<ProcessingResult<R>>> futures = items.stream()
                    .map(item -> processItemAsync(new WorkItem<>(item), items.size()))
                    .collect(Collectors.toList());

            return CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]))
                    .thenApply(v -> futures.stream()
                            .map(CompletableFuture::join)
                            .collect(Collectors.toList()));
        }

        private CompletableFuture<ProcessingResult<R>> processItemAsync(WorkItem<T> item, int totalItems) {
            return CompletableFuture.supplyAsync(() -> {
                try {
                    rateLimiter.acquire();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return new ProcessingResult.Failure<R>(
                            item.getId(), e, 0, Duration.ZERO);
                }

                try {
                    item.setStatus(WorkStatus.PROCESSING);
                    Instant start = Instant.now();
                    ProcessingResult<R> result = processWithRetry(item, start);

                    int current = progress.incrementAndGet();
                    if (progressCallback != null) {
                        progressCallback.accept(String.format(
                                "Progress: %d/%d (%.0f%%)", current, totalItems,
                                (double) current / totalItems * 100));
                    }

                    return result;
                } finally {
                    rateLimiter.release();
                }
            }, executor);
        }

        private ProcessingResult<R> processWithRetry(WorkItem<T> item, Instant start) {
            int attempts = 0;
            Throwable lastError = null;

            while (attempts <= maxRetries) {
                try {
                    CompletableFuture<R> future = CompletableFuture.supplyAsync(
                            () -> processingFunction.apply(item.getPayload()), executor);

                    R result = future.get(itemTimeout.toMillis(), TimeUnit.MILLISECONDS);

                    item.setStatus(WorkStatus.COMPLETED);
                    item.setResult(result);
                    Duration duration = Duration.between(start, Instant.now());
                    metrics.recordSuccess(item.getId(), duration);
                    return new ProcessingResult.Success<>(item.getId(), result, duration);

                } catch (TimeoutException e) {
                    item.setStatus(WorkStatus.TIMED_OUT);
                    Duration duration = Duration.between(start, Instant.now());
                    metrics.recordTimeout(item.getId());
                    return new ProcessingResult.Timeout<>(item.getId(), itemTimeout, duration);

                } catch (Exception e) {
                    lastError = e.getCause() != null ? e.getCause() : e;
                    attempts++;
                    if (attempts <= maxRetries) {
                        metrics.recordRetry();
                        long delay = baseRetryDelay.toMillis() * (1L << (attempts - 1));
                        try {
                            Thread.sleep(delay);
                        } catch (InterruptedException ie) {
                            Thread.currentThread().interrupt();
                            break;
                        }
                    }
                }
            }

            item.setStatus(WorkStatus.FAILED);
            item.setError(lastError);
            Duration duration = Duration.between(start, Instant.now());
            metrics.recordFailure(item.getId(), duration);
            return new ProcessingResult.Failure<>(item.getId(), lastError, attempts, duration);
        }

        public MetricsCollector getMetrics() { return metrics; }

        public void shutdown() {
            executor.shutdown();
            try {
                if (!executor.awaitTermination(30, TimeUnit.SECONDS)) {
                    executor.shutdownNow();
                }
            } catch (InterruptedException e) {
                executor.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }
    }

    // --- Processing Pipeline ---

    public static class ProcessingPipeline<T, R> {
        private final List<PipelineStage<?, ?>> stages = new ArrayList<>();
        private final String name;

        public ProcessingPipeline(String name) {
            this.name = name;
        }

        @SuppressWarnings("unchecked")
        public <I, O> ProcessingPipeline<T, O> addStage(String stageName, Function<I, O> transform) {
            stages.add(new PipelineStage<>(stageName, transform));
            return (ProcessingPipeline<T, O>) this;
        }

        @SuppressWarnings("unchecked")
        public <I> ProcessingPipeline<T, R> addFilter(String stageName, Predicate<I> predicate) {
            stages.add(new FilterStage<>(stageName, predicate));
            return this;
        }

        @SuppressWarnings("unchecked")
        public R execute(T input) {
            Object current = input;
            for (PipelineStage<?, ?> stage : stages) {
                if (stage instanceof FilterStage<?, ?> filter) {
                    Predicate<Object> pred = (Predicate<Object>) filter.predicate;
                    if (!pred.test(current)) {
                        throw new PipelineFilterException(
                                "Item filtered out at stage: " + stage.name);
                    }
                } else {
                    Function<Object, Object> fn = (Function<Object, Object>) stage.transform;
                    current = fn.apply(current);
                }
            }
            return (R) current;
        }

        public String getName() { return name; }
        public int getStageCount() { return stages.size(); }

        private static class PipelineStage<I, O> {
            final String name;
            final Function<I, O> transform;

            PipelineStage(String name, Function<I, O> transform) {
                this.name = name;
                this.transform = transform;
            }
        }

        private static class FilterStage<I, O> extends PipelineStage<I, O> {
            final Predicate<I> predicate;

            FilterStage(String name, Predicate<I> predicate) {
                super(name, null);
                this.predicate = predicate;
            }
        }
    }

    public static class PipelineFilterException extends RuntimeException {
        public PipelineFilterException(String message) {
            super(message);
        }
    }

    // --- Demo Application ---

    public static void main(String[] args) throws Exception {
        System.out.println("=== Async Batch Processor Demo ===\n");

        // Define processing function: square a number with simulated delay
        Function<Integer, String> processNumber = n -> {
            try {
                // Simulate variable processing time
                Thread.sleep(50 + (long) (Math.random() * 200));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }

            // Simulate occasional failures
            if (n % 7 == 0) {
                throw new RuntimeException("Simulated failure for item " + n);
            }

            return String.format("Result(%d -> %d)", n, n * n);
        };

        // Create batch processor
        BatchProcessor<Integer, String> processor = new BatchProcessor<>(
                processNumber,
                4,              // thread pool size
                3,              // max concurrent
                Duration.ofSeconds(2),  // timeout per item
                2,              // max retries
                Duration.ofMillis(100), // base retry delay
                System.out::println    // progress callback
        );

        // Process a batch
        List<Integer> items = new ArrayList<>();
        for (int i = 1; i <= 20; i++) items.add(i);

        System.out.println("Processing " + items.size() + " items...\n");
        Instant start = Instant.now();

        CompletableFuture<List<ProcessingResult<String>>> future = processor.processBatch(items);
        List<ProcessingResult<String>> results = future.get(30, TimeUnit.SECONDS);

        Duration elapsed = Duration.between(start, Instant.now());
        System.out.println("\nCompleted in " + elapsed.toMillis() + "ms\n");

        // Categorize results
        List<ProcessingResult.Success<String>> successes = new ArrayList<>();
        List<ProcessingResult.Failure<String>> failures = new ArrayList<>();
        List<ProcessingResult.Timeout<String>> timeouts = new ArrayList<>();

        for (ProcessingResult<String> result : results) {
            result.fold(
                    s -> { successes.add(s); return null; },
                    f -> { failures.add(f); return null; },
                    t -> { timeouts.add(t); return null; }
            );
        }

        System.out.println("Successes (" + successes.size() + "):");
        for (var s : successes) {
            System.out.printf("  [%s] %s (%.0fms)%n", s.itemId(), s.value(), (double) s.duration().toMillis());
        }

        if (!failures.isEmpty()) {
            System.out.println("\nFailures (" + failures.size() + "):");
            for (var f : failures) {
                System.out.printf("  [%s] %s after %d attempts (%.0fms)%n",
                        f.itemId(), f.error().getMessage(), f.attempts(), (double) f.duration().toMillis());
            }
        }

        if (!timeouts.isEmpty()) {
            System.out.println("\nTimeouts (" + timeouts.size() + "):");
            for (var t : timeouts) {
                System.out.printf("  [%s] timed out after %s%n", t.itemId(), t.timeout());
            }
        }

        // Metrics
        System.out.println("\n" + processor.getMetrics().getSummary());

        // Pipeline demo
        System.out.println("\n=== Pipeline Demo ===\n");

        ProcessingPipeline<String, String> pipeline = new ProcessingPipeline<>("TextProcessor");
        ProcessingPipeline<String, String> configured = pipeline
                .<String>addFilter("NonEmpty", s -> !s.isBlank())
                .<String, String>addStage("Trim", String::trim)
                .<String, String>addStage("Uppercase", String::toUpperCase)
                .<String, String>addStage("AddPrefix", s -> "[PROCESSED] " + s);

        String[] testInputs = {"  hello world  ", "  java to go  ", "", "  pipeline test  "};
        for (String input : testInputs) {
            try {
                String result = configured.execute(input);
                System.out.println("'" + input + "' -> '" + result + "'");
            } catch (PipelineFilterException e) {
                System.out.println("'" + input + "' -> FILTERED: " + e.getMessage());
            }
        }

        processor.shutdown();
        System.out.println("\nProcessor shut down.");
    }
}
