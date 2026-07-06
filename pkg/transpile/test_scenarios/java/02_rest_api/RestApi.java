/**
 * Test Scenario 02: REST API with In-Memory Storage
 * Difficulty: Medium (~250 LOC)
 *
 * Tests:
 * - Java records
 * - Interface with multiple implementations
 * - ConcurrentHashMap for thread-safe storage
 * - AtomicLong for ID generation
 * - Optional handling
 * - LocalDateTime usage
 * - Spring-style annotations (as comments/custom annotations for compilability)
 * - Stream API with filter, map, collect
 * - HTTP-style controller pattern
 *
 * Expected Go mappings:
 * - record Task             -> struct
 * - interface               -> interface
 * - ConcurrentHashMap       -> sync.Map or map with sync.RWMutex
 * - AtomicLong              -> atomic.Int64
 * - Optional<T>             -> (*T, bool) or error
 * - LocalDateTime           -> time.Time
 * - Stream API              -> for loops with slices
 * - @RestController pattern -> net/http handlers
 */

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

public class RestApi {

    // --- Domain Model ---

    public record Task(
            long id,
            String title,
            String description,
            boolean completed,
            LocalDateTime createdAt,
            LocalDateTime updatedAt
    ) {
        public Task withCompleted(boolean completed) {
            return new Task(id, title, description, completed, createdAt, LocalDateTime.now());
        }

        public Task withTitle(String title) {
            return new Task(id, title, description, completed, createdAt, LocalDateTime.now());
        }

        public Task withDescription(String description) {
            return new Task(id, title, description, completed, createdAt, LocalDateTime.now());
        }
    }

    public record CreateTaskRequest(String title, String description) {
        public CreateTaskRequest {
            if (title == null || title.isBlank()) {
                throw new IllegalArgumentException("Title must not be blank");
            }
        }
    }

    public record UpdateTaskRequest(String title, String description, Boolean completed) {}

    public record ApiResponse<T>(int status, String message, T data) {
        public static <T> ApiResponse<T> ok(T data) {
            return new ApiResponse<>(200, "OK", data);
        }

        public static <T> ApiResponse<T> created(T data) {
            return new ApiResponse<>(201, "Created", data);
        }

        public static <T> ApiResponse<T> notFound(String message) {
            return new ApiResponse<>(404, message, null);
        }

        public static <T> ApiResponse<T> badRequest(String message) {
            return new ApiResponse<>(400, message, null);
        }
    }

    // --- Repository Layer ---

    public interface TaskRepository {
        List<Task> findAll();
        Optional<Task> findById(long id);
        Task save(Task task);
        boolean deleteById(long id);
        List<Task> findByCompleted(boolean completed);
        long count();
    }

    public static class InMemoryTaskRepository implements TaskRepository {
        private final Map<Long, Task> store = new ConcurrentHashMap<>();
        private final AtomicLong idGenerator = new AtomicLong(0);

        @Override
        public List<Task> findAll() {
            return new ArrayList<>(store.values());
        }

        @Override
        public Optional<Task> findById(long id) {
            return Optional.ofNullable(store.get(id));
        }

        @Override
        public Task save(Task task) {
            if (task.id() == 0) {
                long newId = idGenerator.incrementAndGet();
                Task newTask = new Task(
                        newId, task.title(), task.description(),
                        task.completed(), LocalDateTime.now(), LocalDateTime.now()
                );
                store.put(newId, newTask);
                return newTask;
            }
            store.put(task.id(), task);
            return task;
        }

        @Override
        public boolean deleteById(long id) {
            return store.remove(id) != null;
        }

        @Override
        public List<Task> findByCompleted(boolean completed) {
            return store.values().stream()
                    .filter(task -> task.completed() == completed)
                    .collect(Collectors.toList());
        }

        @Override
        public long count() {
            return store.size();
        }
    }

    // --- Service Layer ---

    public static class TaskService {
        private final TaskRepository repository;

        public TaskService(TaskRepository repository) {
            this.repository = repository;
        }

        public Task createTask(CreateTaskRequest request) {
            Task task = new Task(0, request.title(), request.description(),
                    false, LocalDateTime.now(), LocalDateTime.now());
            return repository.save(task);
        }

        public Optional<Task> getTask(long id) {
            return repository.findById(id);
        }

        public List<Task> getAllTasks() {
            return repository.findAll();
        }

        public List<Task> getTasksByStatus(boolean completed) {
            return repository.findByCompleted(completed);
        }

        public Optional<Task> updateTask(long id, UpdateTaskRequest request) {
            return repository.findById(id).map(existing -> {
                Task updated = existing;
                if (request.title() != null) {
                    updated = updated.withTitle(request.title());
                }
                if (request.description() != null) {
                    updated = updated.withDescription(request.description());
                }
                if (request.completed() != null) {
                    updated = updated.withCompleted(request.completed());
                }
                return repository.save(updated);
            });
        }

        public Optional<Task> completeTask(long id) {
            return repository.findById(id).map(task -> {
                Task completed = task.withCompleted(true);
                return repository.save(completed);
            });
        }

        public boolean deleteTask(long id) {
            return repository.deleteById(id);
        }

        public long getTaskCount() {
            return repository.count();
        }
    }

    // --- Controller Layer ---

    public static class TaskController {
        private final TaskService service;

        public TaskController(TaskService service) {
            this.service = service;
        }

        // GET /tasks
        public ApiResponse<List<Task>> getAllTasks(Boolean completed) {
            List<Task> tasks;
            if (completed != null) {
                tasks = service.getTasksByStatus(completed);
            } else {
                tasks = service.getAllTasks();
            }
            return ApiResponse.ok(tasks);
        }

        // GET /tasks/{id}
        public ApiResponse<Task> getTask(long id) {
            return service.getTask(id)
                    .map(ApiResponse::ok)
                    .orElse(ApiResponse.notFound("Task not found: " + id));
        }

        // POST /tasks
        public ApiResponse<Task> createTask(CreateTaskRequest request) {
            try {
                Task task = service.createTask(request);
                return ApiResponse.created(task);
            } catch (IllegalArgumentException e) {
                return ApiResponse.badRequest(e.getMessage());
            }
        }

        // PUT /tasks/{id}
        public ApiResponse<Task> updateTask(long id, UpdateTaskRequest request) {
            return service.updateTask(id, request)
                    .map(ApiResponse::ok)
                    .orElse(ApiResponse.notFound("Task not found: " + id));
        }

        // PUT /tasks/{id}/complete
        public ApiResponse<Task> completeTask(long id) {
            return service.completeTask(id)
                    .map(ApiResponse::ok)
                    .orElse(ApiResponse.notFound("Task not found: " + id));
        }

        // DELETE /tasks/{id}
        public ApiResponse<Void> deleteTask(long id) {
            if (service.deleteTask(id)) {
                return ApiResponse.ok(null);
            }
            return ApiResponse.notFound("Task not found: " + id);
        }
    }

    // --- Application Entry Point ---

    public static void main(String[] args) {
        TaskRepository repository = new InMemoryTaskRepository();
        TaskService service = new TaskService(repository);
        TaskController controller = new TaskController(service);

        DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

        System.out.println("=== REST API Demo ===\n");

        // Create tasks
        var created1 = controller.createTask(new CreateTaskRequest("Buy groceries", "Milk, eggs, bread"));
        var created2 = controller.createTask(new CreateTaskRequest("Write tests", "Unit and integration tests"));
        var created3 = controller.createTask(new CreateTaskRequest("Deploy app", "Push to production"));

        System.out.println("Created 3 tasks");
        System.out.println("Task 1: " + created1.data().title() + " (id=" + created1.data().id() + ")");
        System.out.println("Task 2: " + created2.data().title() + " (id=" + created2.data().id() + ")");
        System.out.println("Task 3: " + created3.data().title() + " (id=" + created3.data().id() + ")");

        // Complete a task
        controller.completeTask(1);
        System.out.println("\nCompleted task 1");

        // Get all tasks
        var allTasks = controller.getAllTasks(null);
        System.out.println("\nAll tasks (" + allTasks.data().size() + "):");
        for (Task task : allTasks.data()) {
            System.out.printf("  [%s] %s - %s (%s)%n",
                    task.completed() ? "x" : " ",
                    task.title(),
                    task.description(),
                    task.createdAt().format(dtf));
        }

        // Get incomplete tasks
        var incomplete = controller.getAllTasks(false);
        System.out.println("\nIncomplete tasks: " + incomplete.data().size());

        // Update a task
        controller.updateTask(2, new UpdateTaskRequest("Write ALL tests", null, null));
        var updated = controller.getTask(2);
        System.out.println("Updated task 2 title: " + updated.data().title());

        // Delete a task
        controller.deleteTask(3);
        System.out.println("\nDeleted task 3");
        System.out.println("Total tasks: " + service.getTaskCount());

        // Try to get deleted task
        var notFound = controller.getTask(3);
        System.out.println("Get deleted task: " + notFound.message());
    }
}
