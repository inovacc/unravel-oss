/**
 * Test Scenario 05: Kafka-Based Event Processing Pipeline
 * Difficulty: Very Hard (~600 LOC)
 *
 * Tests:
 * - Generic event types with metadata maps
 * - Serialization/deserialization abstraction (Jackson ObjectMapper pattern)
 * - Kafka producer/consumer wrappers with configuration
 * - Event processor interface with multiple implementations
 * - Filter, Transform, and Aggregate processor patterns
 * - Fluent builder API for pipeline construction
 * - Dead letter queue handling
 * - Metrics with atomic counters
 * - Consumer group management with rebalance listeners
 * - Functional programming (Predicate, Function, BiFunction)
 * - SLF4J logging pattern
 * - AutoCloseable / try-with-resources
 * - Concurrent collections for thread-safe state
 *
 * Expected Go mappings:
 * - Generic Event<T>          -> struct with interface{} or generics
 * - ObjectMapper              -> encoding/json
 * - KafkaProducer             -> sarama or confluent-kafka-go producer
 * - KafkaConsumer             -> sarama or confluent-kafka-go consumer
 * - EventProcessor interface  -> interface
 * - Builder pattern           -> functional options
 * - AutoCloseable             -> io.Closer
 * - SLF4J                     -> log/slog
 * - ConcurrentHashMap         -> sync.Map
 * - Predicate/Function        -> func types
 */

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.logging.Level;
import java.util.logging.Logger;

public class KafkaPipeline {

    // --- Logger (simulating SLF4J) ---
    private static final Logger log = Logger.getLogger(KafkaPipeline.class.getName());

    // --- Event Model ---

    public static class Event<T> {
        private final String id;
        private final String type;
        private final T payload;
        private final Instant timestamp;
        private final Map<String, String> metadata;
        private final String source;
        private final int partition;

        public Event(String type, T payload, String source) {
            this(UUID.randomUUID().toString(), type, payload, Instant.now(),
                    new HashMap<>(), source, -1);
        }

        public Event(String id, String type, T payload, Instant timestamp,
                     Map<String, String> metadata, String source, int partition) {
            this.id = Objects.requireNonNull(id);
            this.type = Objects.requireNonNull(type);
            this.payload = payload;
            this.timestamp = Objects.requireNonNull(timestamp);
            this.metadata = new HashMap<>(metadata);
            this.source = source;
            this.partition = partition;
        }

        public String getId() { return id; }
        public String getType() { return type; }
        public T getPayload() { return payload; }
        public Instant getTimestamp() { return timestamp; }
        public Map<String, String> getMetadata() { return Collections.unmodifiableMap(metadata); }
        public String getSource() { return source; }
        public int getPartition() { return partition; }

        public Event<T> withMetadata(String key, String value) {
            Map<String, String> newMeta = new HashMap<>(this.metadata);
            newMeta.put(key, value);
            return new Event<>(id, type, payload, timestamp, newMeta, source, partition);
        }

        public <R> Event<R> mapPayload(Function<T, R> mapper) {
            return new Event<>(id, type, mapper.apply(payload), timestamp, metadata, source, partition);
        }

        @Override
        public String toString() {
            return String.format("Event{id=%s, type=%s, payload=%s, source=%s}",
                    id.substring(0, 8), type, payload, source);
        }
    }

    // --- Serialization ---

    public interface EventSerializer<T> {
        String serialize(Event<T> event);
    }

    public interface EventDeserializer<T> {
        Event<T> deserialize(String data, Class<T> payloadType);
    }

    public static class JsonEventSerializer<T> implements EventSerializer<T> {
        @Override
        public String serialize(Event<T> event) {
            // Simplified JSON serialization (would use Jackson ObjectMapper in production)
            return String.format(
                    "{\"id\":\"%s\",\"type\":\"%s\",\"payload\":\"%s\",\"timestamp\":\"%s\",\"source\":\"%s\"}",
                    event.getId(), event.getType(), event.getPayload(),
                    event.getTimestamp(), event.getSource());
        }
    }

    public static class JsonEventDeserializer<T> implements EventDeserializer<T> {
        @Override
        public Event<T> deserialize(String data, Class<T> payloadType) {
            // Simplified deserialization (would use Jackson ObjectMapper in production)
            // In real code: objectMapper.readValue(data, new TypeReference<Event<T>>(){})
            log.fine("Deserializing event: " + data.substring(0, Math.min(50, data.length())));
            return null; // Placeholder
        }
    }

    // --- Kafka Producer Wrapper ---

    public static class KafkaEventProducer<T> implements AutoCloseable {
        private final String topic;
        private final EventSerializer<T> serializer;
        private final AtomicLong messagesSent = new AtomicLong(0);
        private final AtomicBoolean closed = new AtomicBoolean(false);
        private final Properties config;

        public KafkaEventProducer(String topic, EventSerializer<T> serializer, Properties config) {
            this.topic = Objects.requireNonNull(topic);
            this.serializer = Objects.requireNonNull(serializer);
            this.config = new Properties(config);
            log.info("KafkaEventProducer created for topic: " + topic);
        }

        public void send(Event<T> event) {
            if (closed.get()) {
                throw new IllegalStateException("Producer is closed");
            }
            String serialized = serializer.serialize(event);
            // In production: kafkaProducer.send(new ProducerRecord<>(topic, event.getId(), serialized))
            log.fine("Sent to " + topic + ": " + serialized.substring(0, Math.min(80, serialized.length())));
            messagesSent.incrementAndGet();
        }

        public void sendWithKey(String key, Event<T> event) {
            if (closed.get()) {
                throw new IllegalStateException("Producer is closed");
            }
            String serialized = serializer.serialize(event);
            log.fine("Sent to " + topic + " [key=" + key + "]: " + event.getId());
            messagesSent.incrementAndGet();
        }

        public long getMessagesSent() { return messagesSent.get(); }
        public String getTopic() { return topic; }

        @Override
        public void close() {
            if (closed.compareAndSet(false, true)) {
                log.info("Closing producer for topic: " + topic + " (sent " + messagesSent.get() + " messages)");
            }
        }
    }

    // --- Kafka Consumer Wrapper ---

    public static class KafkaEventConsumer<T> implements AutoCloseable {
        private final String topic;
        private final String groupId;
        private final EventDeserializer<T> deserializer;
        private final Class<T> payloadType;
        private final AtomicBoolean running = new AtomicBoolean(false);
        private final AtomicLong messagesReceived = new AtomicLong(0);
        private final List<ConsumerRebalanceCallback> rebalanceCallbacks = new CopyOnWriteArrayList<>();
        private final Properties config;

        public interface ConsumerRebalanceCallback {
            void onPartitionsAssigned(List<Integer> partitions);
            void onPartitionsRevoked(List<Integer> partitions);
        }

        public KafkaEventConsumer(String topic, String groupId,
                                  EventDeserializer<T> deserializer, Class<T> payloadType,
                                  Properties config) {
            this.topic = Objects.requireNonNull(topic);
            this.groupId = Objects.requireNonNull(groupId);
            this.deserializer = Objects.requireNonNull(deserializer);
            this.payloadType = Objects.requireNonNull(payloadType);
            this.config = new Properties(config);
            log.info("KafkaEventConsumer created for topic: " + topic + " group: " + groupId);
        }

        public void addRebalanceCallback(ConsumerRebalanceCallback callback) {
            rebalanceCallbacks.add(callback);
        }

        public void startConsuming(java.util.function.Consumer<Event<T>> handler) {
            if (!running.compareAndSet(false, true)) {
                throw new IllegalStateException("Consumer is already running");
            }
            log.info("Started consuming from topic: " + topic);
            // In production: poll loop with kafkaConsumer.poll(Duration)
        }

        public void stopConsuming() {
            if (running.compareAndSet(true, false)) {
                log.info("Stopped consuming from topic: " + topic);
            }
        }

        public long getMessagesReceived() { return messagesReceived.get(); }
        public boolean isRunning() { return running.get(); }

        @Override
        public void close() {
            stopConsuming();
            log.info("Closing consumer for topic: " + topic + " (received " + messagesReceived.get() + " messages)");
        }
    }

    // --- Event Processor Interface ---

    public interface EventProcessor<T> {
        List<Event<T>> process(Event<T> event);
        void onError(Event<T> event, Exception exception);
        String getName();
    }

    // --- Filter Processor ---

    public static class FilterProcessor<T> implements EventProcessor<T> {
        private final String name;
        private final Predicate<Event<T>> predicate;
        private final AtomicLong filtered = new AtomicLong(0);
        private final AtomicLong passed = new AtomicLong(0);

        public FilterProcessor(String name, Predicate<Event<T>> predicate) {
            this.name = name;
            this.predicate = predicate;
        }

        @Override
        public List<Event<T>> process(Event<T> event) {
            if (predicate.test(event)) {
                passed.incrementAndGet();
                return List.of(event.withMetadata("filter." + name, "passed"));
            }
            filtered.incrementAndGet();
            log.fine("Event " + event.getId() + " filtered by " + name);
            return List.of();
        }

        @Override
        public void onError(Event<T> event, Exception exception) {
            log.log(Level.WARNING, "Filter error on event " + event.getId(), exception);
        }

        @Override
        public String getName() { return "Filter:" + name; }

        public long getFilteredCount() { return filtered.get(); }
        public long getPassedCount() { return passed.get(); }
    }

    // --- Transform Processor ---

    public static class TransformProcessor<T, R> implements EventProcessor<T> {
        private final String name;
        private final Function<T, R> transformer;
        private final String outputType;
        private final AtomicLong transformed = new AtomicLong(0);

        public TransformProcessor(String name, Function<T, R> transformer, String outputType) {
            this.name = name;
            this.transformer = transformer;
            this.outputType = outputType;
        }

        @Override
        @SuppressWarnings("unchecked")
        public List<Event<T>> process(Event<T> event) {
            R result = transformer.apply(event.getPayload());
            transformed.incrementAndGet();
            Event<R> transformedEvent = event.mapPayload(p -> result)
                    .withMetadata("transform." + name, "applied");
            return List.of((Event<T>) transformedEvent);
        }

        @Override
        public void onError(Event<T> event, Exception exception) {
            log.log(Level.WARNING, "Transform error on event " + event.getId(), exception);
        }

        @Override
        public String getName() { return "Transform:" + name; }

        public long getTransformedCount() { return transformed.get(); }
    }

    // --- Aggregate Processor ---

    public static class AggregateProcessor<T, A> implements EventProcessor<T> {
        private final String name;
        private final Function<T, String> keyExtractor;
        private final BiFunction<A, T, A> accumulator;
        private final A initialValue;
        private final ConcurrentHashMap<String, A> state = new ConcurrentHashMap<>();
        private final Duration windowSize;
        private final Instant windowStart;

        public AggregateProcessor(String name, Function<T, String> keyExtractor,
                                  BiFunction<A, T, A> accumulator, A initialValue,
                                  Duration windowSize) {
            this.name = name;
            this.keyExtractor = keyExtractor;
            this.accumulator = accumulator;
            this.initialValue = initialValue;
            this.windowSize = windowSize;
            this.windowStart = Instant.now();
        }

        @Override
        public List<Event<T>> process(Event<T> event) {
            String key = keyExtractor.apply(event.getPayload());
            state.compute(key, (k, current) ->
                    accumulator.apply(current != null ? current : initialValue, event.getPayload()));
            log.fine("Aggregated event " + event.getId() + " with key: " + key);
            return List.of(event.withMetadata("aggregate." + name, "key=" + key));
        }

        @Override
        public void onError(Event<T> event, Exception exception) {
            log.log(Level.WARNING, "Aggregate error on event " + event.getId(), exception);
        }

        @Override
        public String getName() { return "Aggregate:" + name; }

        public Map<String, A> getState() { return Collections.unmodifiableMap(state); }

        public boolean isWindowExpired() {
            return Duration.between(windowStart, Instant.now()).compareTo(windowSize) > 0;
        }
    }

    // --- Dead Letter Handler ---

    public static class DeadLetterHandler<T> {
        private final String deadLetterTopic;
        private final KafkaEventProducer<T> producer;
        private final AtomicLong deadLetterCount = new AtomicLong(0);
        private final int maxRetries;

        public DeadLetterHandler(String deadLetterTopic, KafkaEventProducer<T> producer, int maxRetries) {
            this.deadLetterTopic = deadLetterTopic;
            this.producer = producer;
            this.maxRetries = maxRetries;
        }

        public void handle(Event<T> event, Exception exception, int attemptNumber) {
            Event<T> dlqEvent = event
                    .withMetadata("dlq.reason", exception.getMessage())
                    .withMetadata("dlq.attempt", String.valueOf(attemptNumber))
                    .withMetadata("dlq.maxRetries", String.valueOf(maxRetries))
                    .withMetadata("dlq.originalTopic", event.getSource())
                    .withMetadata("dlq.timestamp", Instant.now().toString());

            producer.send(dlqEvent);
            deadLetterCount.incrementAndGet();
            log.warning(String.format("Event %s sent to DLQ %s after %d attempts: %s",
                    event.getId(), deadLetterTopic, attemptNumber, exception.getMessage()));
        }

        public long getDeadLetterCount() { return deadLetterCount.get(); }
    }

    // --- Pipeline Metrics ---

    public static class PipelineMetrics {
        private final AtomicLong eventsProcessed = new AtomicLong(0);
        private final AtomicLong eventsFiltered = new AtomicLong(0);
        private final AtomicLong eventsFailed = new AtomicLong(0);
        private final AtomicLong eventsRetried = new AtomicLong(0);
        private final ConcurrentHashMap<String, AtomicLong> processorCounts = new ConcurrentHashMap<>();
        private final Instant createdAt = Instant.now();

        public void recordProcessed(String processorName) {
            eventsProcessed.incrementAndGet();
            processorCounts.computeIfAbsent(processorName, k -> new AtomicLong(0)).incrementAndGet();
        }

        public void recordFiltered() { eventsFiltered.incrementAndGet(); }
        public void recordFailed() { eventsFailed.incrementAndGet(); }
        public void recordRetried() { eventsRetried.incrementAndGet(); }

        public long getEventsProcessed() { return eventsProcessed.get(); }
        public long getEventsFiltered() { return eventsFiltered.get(); }
        public long getEventsFailed() { return eventsFailed.get(); }
        public long getEventsRetried() { return eventsRetried.get(); }
        public Duration getUptime() { return Duration.between(createdAt, Instant.now()); }

        public Map<String, Long> getProcessorCounts() {
            Map<String, Long> counts = new HashMap<>();
            processorCounts.forEach((k, v) -> counts.put(k, v.get()));
            return counts;
        }

        public String getSummary() {
            return String.format(
                    "PipelineMetrics{processed=%d, filtered=%d, failed=%d, retried=%d, uptime=%s, processors=%s}",
                    eventsProcessed.get(), eventsFiltered.get(), eventsFailed.get(),
                    eventsRetried.get(), getUptime(), getProcessorCounts());
        }
    }

    // --- Pipeline Builder ---

    public static class PipelineBuilder<T> {
        private final String name;
        private final String sourceTopic;
        private final List<EventProcessor<T>> processors = new ArrayList<>();
        private String sinkTopic;
        private String deadLetterTopic;
        private int maxRetries = 3;
        private int parallelism = 1;
        private Properties kafkaConfig = new Properties();

        private PipelineBuilder(String name, String sourceTopic) {
            this.name = name;
            this.sourceTopic = sourceTopic;
        }

        public static <T> PipelineBuilder<T> from(String name, String sourceTopic) {
            return new PipelineBuilder<>(name, sourceTopic);
        }

        public PipelineBuilder<T> filter(String filterName, Predicate<Event<T>> predicate) {
            processors.add(new FilterProcessor<>(filterName, predicate));
            return this;
        }

        @SuppressWarnings("unchecked")
        public <R> PipelineBuilder<T> transform(String name, Function<T, R> transformer) {
            processors.add((EventProcessor<T>) new TransformProcessor<>(name, transformer, "transformed"));
            return this;
        }

        public PipelineBuilder<T> aggregate(String name, Function<T, String> keyExtractor,
                                             BiFunction<Long, T, Long> accumulator,
                                             Duration windowSize) {
            processors.add((EventProcessor<T>) new AggregateProcessor<>(
                    name, keyExtractor, accumulator, 0L, windowSize));
            return this;
        }

        public PipelineBuilder<T> addProcessor(EventProcessor<T> processor) {
            processors.add(processor);
            return this;
        }

        public PipelineBuilder<T> to(String sinkTopic) {
            this.sinkTopic = sinkTopic;
            return this;
        }

        public PipelineBuilder<T> withDeadLetterQueue(String dlqTopic) {
            this.deadLetterTopic = dlqTopic;
            return this;
        }

        public PipelineBuilder<T> withMaxRetries(int maxRetries) {
            this.maxRetries = maxRetries;
            return this;
        }

        public PipelineBuilder<T> withParallelism(int parallelism) {
            this.parallelism = parallelism;
            return this;
        }

        public PipelineBuilder<T> withKafkaConfig(Properties config) {
            this.kafkaConfig = new Properties(config);
            return this;
        }

        public Pipeline<T> build() {
            Objects.requireNonNull(sinkTopic, "Sink topic must be specified");
            return new Pipeline<>(name, sourceTopic, sinkTopic, deadLetterTopic,
                    processors, maxRetries, parallelism, kafkaConfig);
        }
    }

    // --- Pipeline ---

    public static class Pipeline<T> implements AutoCloseable {
        private final String name;
        private final String sourceTopic;
        private final String sinkTopic;
        private final String deadLetterTopic;
        private final List<EventProcessor<T>> processors;
        private final int maxRetries;
        private final PipelineMetrics metrics;
        private final ExecutorService executor;
        private final AtomicBoolean running = new AtomicBoolean(false);
        private final Properties kafkaConfig;

        Pipeline(String name, String sourceTopic, String sinkTopic, String deadLetterTopic,
                 List<EventProcessor<T>> processors, int maxRetries, int parallelism,
                 Properties kafkaConfig) {
            this.name = name;
            this.sourceTopic = sourceTopic;
            this.sinkTopic = sinkTopic;
            this.deadLetterTopic = deadLetterTopic;
            this.processors = new ArrayList<>(processors);
            this.maxRetries = maxRetries;
            this.metrics = new PipelineMetrics();
            this.executor = Executors.newFixedThreadPool(parallelism);
            this.kafkaConfig = kafkaConfig;
        }

        public void processEvent(Event<T> event) {
            List<Event<T>> current = List.of(event);

            for (EventProcessor<T> processor : processors) {
                List<Event<T>> next = new ArrayList<>();
                for (Event<T> e : current) {
                    try {
                        List<Event<T>> results = processor.process(e);
                        next.addAll(results);
                        metrics.recordProcessed(processor.getName());
                    } catch (Exception ex) {
                        processor.onError(e, ex);
                        metrics.recordFailed();
                        log.log(Level.SEVERE, "Pipeline " + name + " error at " + processor.getName(), ex);
                    }
                }
                current = next;
                if (current.isEmpty()) {
                    metrics.recordFiltered();
                    return;
                }
            }

            for (Event<T> outputEvent : current) {
                log.fine("Pipeline " + name + " output to " + sinkTopic + ": " + outputEvent.getId());
            }
        }

        public void start() {
            if (running.compareAndSet(false, true)) {
                log.info("Starting pipeline: " + name + " (" + sourceTopic + " -> " + sinkTopic + ")");
                log.info("Processors: " + processors.stream()
                        .map(EventProcessor::getName)
                        .reduce((a, b) -> a + " -> " + b)
                        .orElse("none"));
            }
        }

        public void stop() {
            if (running.compareAndSet(true, false)) {
                log.info("Stopping pipeline: " + name);
            }
        }

        public PipelineMetrics getMetrics() { return metrics; }
        public String getName() { return name; }
        public boolean isRunning() { return running.get(); }

        @Override
        public void close() {
            stop();
            executor.shutdown();
            try {
                if (!executor.awaitTermination(10, TimeUnit.SECONDS)) {
                    executor.shutdownNow();
                }
            } catch (InterruptedException e) {
                executor.shutdownNow();
                Thread.currentThread().interrupt();
            }
            log.info("Pipeline " + name + " closed. " + metrics.getSummary());
        }
    }

    // --- Demo Application ---

    public static void main(String[] args) {
        System.out.println("=== Kafka Pipeline Demo ===\n");

        // Build pipeline
        Pipeline<String> pipeline = PipelineBuilder.<String>from("OrderPipeline", "orders.raw")
                .filter("NonEmpty", event -> event.getPayload() != null && !event.getPayload().isBlank())
                .filter("NotTest", event -> !event.getPayload().startsWith("TEST:"))
                .transform("Uppercase", String::toUpperCase)
                .transform("AddTimestamp", s -> s + " [" + Instant.now() + "]")
                .to("orders.processed")
                .withDeadLetterQueue("orders.dlq")
                .withMaxRetries(3)
                .withParallelism(4)
                .build();

        try (pipeline) {
            pipeline.start();
            System.out.println("Pipeline started: " + pipeline.getName());
            System.out.println();

            // Simulate events
            String[] orders = {
                    "order-001: 2x Widget",
                    "order-002: 1x Gadget",
                    "",
                    "TEST: ignore this",
                    "order-003: 5x Doohickey",
                    "order-004: 3x Thingamajig",
                    null,
                    "order-005: 1x Whatchamacallit"
            };

            int eventCount = 0;
            for (String order : orders) {
                Event<String> event = new Event<>("order.created", order, "order-service");
                System.out.println("Input:  " + event);
                pipeline.processEvent(event);
                eventCount++;
            }

            System.out.println("\nProcessed " + eventCount + " events");
            System.out.println("\n" + pipeline.getMetrics().getSummary());

            // Demonstrate aggregate processor
            System.out.println("\n--- Aggregation Demo ---\n");

            AggregateProcessor<String, Long> countAgg = new AggregateProcessor<>(
                    "OrderCount",
                    s -> s != null && s.contains(":") ? s.split(":")[0].trim() : "unknown",
                    (count, item) -> count + 1,
                    0L,
                    Duration.ofMinutes(5)
            );

            for (String order : orders) {
                if (order != null && !order.isBlank()) {
                    Event<String> event = new Event<>("order.created", order, "order-service");
                    countAgg.process(event);
                }
            }

            System.out.println("Aggregation state:");
            countAgg.getState().forEach((key, count) ->
                    System.out.printf("  %s: %d events%n", key, count));

            // Demonstrate producer/consumer
            System.out.println("\n--- Producer/Consumer Demo ---\n");

            Properties props = new Properties();
            props.setProperty("bootstrap.servers", "localhost:9092");

            try (KafkaEventProducer<String> producer = new KafkaEventProducer<>(
                    "demo.topic", new JsonEventSerializer<>(), props)) {

                for (int i = 0; i < 5; i++) {
                    Event<String> event = new Event<>("demo", "message-" + i, "demo-app");
                    producer.send(event);
                }
                System.out.println("Producer sent " + producer.getMessagesSent() + " messages");
            }

        } // pipeline.close() called automatically

        System.out.println("\nPipeline demo complete.");
    }
}
