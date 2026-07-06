/**
 * Test Scenario 03: Data Service with JPA Entities and Repository Patterns
 * Difficulty: Medium-Hard (~400 LOC)
 *
 * Tests:
 * - JPA entity annotations (@Entity, @Id, @GeneratedValue, @Column, @Enumerated)
 * - Embeddable types (@Embeddable, @ElementCollection)
 * - Lombok annotations (@Data, @Builder, @NoArgsConstructor, @AllArgsConstructor, @Slf4j)
 * - Repository pattern with JpaRepository-style interface
 * - Custom @Query methods
 * - BigDecimal for monetary values
 * - Enum with fields and methods
 * - Builder pattern
 * - Validation logic
 * - Stream API with complex operations
 * - Optional chaining
 *
 * Expected Go mappings:
 * - @Entity class          -> struct (JPA annotations stripped)
 * - @Embeddable            -> nested struct
 * - @Data (Lombok)         -> struct with exported fields
 * - @Builder               -> NewXxx functional options or builder struct
 * - BigDecimal             -> decimal type or float64 with comment
 * - JpaRepository          -> interface with method signatures
 * - @Query                 -> SQL string constant
 * - @Enumerated            -> int/string const iota
 * - Stream operations      -> for loops
 * - @Slf4j                 -> log/slog
 */

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

public class DataService {

    // --- Enums ---

    public enum UserRole {
        ADMIN("Administrator", 100),
        MANAGER("Manager", 50),
        USER("Standard User", 10),
        GUEST("Guest", 1);

        private final String displayName;
        private final int permissionLevel;

        UserRole(String displayName, int permissionLevel) {
            this.displayName = displayName;
            this.permissionLevel = permissionLevel;
        }

        public String getDisplayName() { return displayName; }
        public int getPermissionLevel() { return permissionLevel; }

        public boolean canManageUsers() {
            return permissionLevel >= 50;
        }
    }

    public enum OrderStatus {
        PENDING, CONFIRMED, PROCESSING, SHIPPED, DELIVERED, CANCELLED, REFUNDED;

        public boolean isTerminal() {
            return this == DELIVERED || this == CANCELLED || this == REFUNDED;
        }

        public boolean canTransitionTo(OrderStatus next) {
            return switch (this) {
                case PENDING -> next == CONFIRMED || next == CANCELLED;
                case CONFIRMED -> next == PROCESSING || next == CANCELLED;
                case PROCESSING -> next == SHIPPED || next == CANCELLED;
                case SHIPPED -> next == DELIVERED;
                case DELIVERED -> next == REFUNDED;
                case CANCELLED, REFUNDED -> false;
            };
        }
    }

    // --- Entity: User ---
    // @Entity @Table(name = "users")
    // @Data @Builder @NoArgsConstructor @AllArgsConstructor
    public static class User {
        // @Id @GeneratedValue(strategy = GenerationType.UUID)
        private String id;

        // @Column(nullable = false, unique = true, length = 50)
        private String username;

        // @Column(nullable = false, unique = true)
        private String email;

        // @Column(nullable = false)
        private String passwordHash;

        // @Enumerated(EnumType.STRING)
        // @Column(nullable = false)
        private UserRole role;

        // @Column(nullable = false, updatable = false)
        private LocalDateTime createdAt;

        // @Column(nullable = false)
        private LocalDateTime updatedAt;

        private boolean active;

        // Builder-style constructor
        public User(String username, String email, String passwordHash, UserRole role) {
            this.id = UUID.randomUUID().toString();
            this.username = username;
            this.email = email;
            this.passwordHash = passwordHash;
            this.role = role;
            this.createdAt = LocalDateTime.now();
            this.updatedAt = LocalDateTime.now();
            this.active = true;
        }

        // Getters
        public String getId() { return id; }
        public String getUsername() { return username; }
        public String getEmail() { return email; }
        public String getPasswordHash() { return passwordHash; }
        public UserRole getRole() { return role; }
        public LocalDateTime getCreatedAt() { return createdAt; }
        public LocalDateTime getUpdatedAt() { return updatedAt; }
        public boolean isActive() { return active; }

        // Setters
        public void setEmail(String email) { this.email = email; this.updatedAt = LocalDateTime.now(); }
        public void setRole(UserRole role) { this.role = role; this.updatedAt = LocalDateTime.now(); }
        public void setActive(boolean active) { this.active = active; this.updatedAt = LocalDateTime.now(); }

        @Override
        public String toString() {
            return String.format("User{id=%s, username=%s, role=%s, active=%s}", id.substring(0, 8), username, role, active);
        }
    }

    // --- Embeddable: OrderItem ---
    // @Embeddable
    // @Data @Builder @NoArgsConstructor @AllArgsConstructor
    public static class OrderItem {
        private String productId;
        private String name;
        private int quantity;
        private BigDecimal price;

        public OrderItem(String productId, String name, int quantity, BigDecimal price) {
            this.productId = productId;
            this.name = name;
            this.quantity = quantity;
            this.price = price;
        }

        public BigDecimal getSubtotal() {
            return price.multiply(BigDecimal.valueOf(quantity)).setScale(2, RoundingMode.HALF_UP);
        }

        public String getProductId() { return productId; }
        public String getName() { return name; }
        public int getQuantity() { return quantity; }
        public BigDecimal getPrice() { return price; }

        @Override
        public String toString() {
            return String.format("%s x%d @ $%s = $%s", name, quantity, price, getSubtotal());
        }
    }

    // --- Entity: Order ---
    // @Entity @Table(name = "orders")
    // @Data @Builder @NoArgsConstructor @AllArgsConstructor
    public static class Order {
        // @Id @GeneratedValue(strategy = GenerationType.UUID)
        private String id;

        // @Column(nullable = false)
        private String userId;

        // @ElementCollection @CollectionTable(name = "order_items")
        private List<OrderItem> items;

        // @Column(nullable = false, precision = 10, scale = 2)
        private BigDecimal total;

        // @Enumerated(EnumType.STRING)
        private OrderStatus status;

        private LocalDateTime createdAt;
        private LocalDateTime updatedAt;

        public Order(String userId, List<OrderItem> items) {
            this.id = UUID.randomUUID().toString();
            this.userId = userId;
            this.items = new ArrayList<>(items);
            this.total = calculateTotal();
            this.status = OrderStatus.PENDING;
            this.createdAt = LocalDateTime.now();
            this.updatedAt = LocalDateTime.now();
        }

        private BigDecimal calculateTotal() {
            return items.stream()
                    .map(OrderItem::getSubtotal)
                    .reduce(BigDecimal.ZERO, BigDecimal::add)
                    .setScale(2, RoundingMode.HALF_UP);
        }

        public void transitionTo(OrderStatus newStatus) {
            if (!status.canTransitionTo(newStatus)) {
                throw new IllegalStateException(
                        String.format("Cannot transition order from %s to %s", status, newStatus));
            }
            this.status = newStatus;
            this.updatedAt = LocalDateTime.now();
        }

        public String getId() { return id; }
        public String getUserId() { return userId; }
        public List<OrderItem> getItems() { return Collections.unmodifiableList(items); }
        public BigDecimal getTotal() { return total; }
        public OrderStatus getStatus() { return status; }
        public LocalDateTime getCreatedAt() { return createdAt; }

        @Override
        public String toString() {
            return String.format("Order{id=%s, items=%d, total=$%s, status=%s}",
                    id.substring(0, 8), items.size(), total, status);
        }
    }

    // --- Repository Interfaces ---

    // public interface UserRepository extends JpaRepository<User, String>
    public interface UserRepository {
        Optional<User> findById(String id);
        Optional<User> findByUsername(String username);
        Optional<User> findByEmail(String email);
        List<User> findByRole(UserRole role);
        List<User> findByActiveTrue();
        User save(User user);
        void deleteById(String id);
        long count();
    }

    // public interface OrderRepository extends JpaRepository<Order, String>
    public interface OrderRepository {
        Optional<Order> findById(String id);
        List<Order> findByUserId(String userId);
        List<Order> findByStatus(OrderStatus status);
        // @Query("SELECT o FROM Order o WHERE o.total >= :minAmount")
        List<Order> findByTotalGreaterThanEqual(BigDecimal minAmount);
        // @Query("SELECT o FROM Order o WHERE o.userId = :userId AND o.status = :status")
        List<Order> findByUserIdAndStatus(String userId, OrderStatus status);
        Order save(Order order);
        void deleteById(String id);
        long count();
    }

    // --- Data Validator ---

    public static class DataValidator {
        private static final int MIN_USERNAME_LENGTH = 3;
        private static final int MAX_USERNAME_LENGTH = 50;
        private static final String EMAIL_REGEX = "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+$";

        public record ValidationResult(boolean valid, List<String> errors) {
            public static ValidationResult ok() {
                return new ValidationResult(true, List.of());
            }

            public static ValidationResult fail(List<String> errors) {
                return new ValidationResult(false, errors);
            }
        }

        public static ValidationResult validateUser(String username, String email, String password) {
            List<String> errors = new ArrayList<>();

            if (username == null || username.isBlank()) {
                errors.add("Username must not be blank");
            } else if (username.length() < MIN_USERNAME_LENGTH) {
                errors.add("Username must be at least " + MIN_USERNAME_LENGTH + " characters");
            } else if (username.length() > MAX_USERNAME_LENGTH) {
                errors.add("Username must not exceed " + MAX_USERNAME_LENGTH + " characters");
            }

            if (email == null || !email.matches(EMAIL_REGEX)) {
                errors.add("Invalid email format");
            }

            if (password == null || password.length() < 8) {
                errors.add("Password must be at least 8 characters");
            } else {
                if (!password.matches(".*[A-Z].*")) errors.add("Password must contain uppercase letter");
                if (!password.matches(".*[a-z].*")) errors.add("Password must contain lowercase letter");
                if (!password.matches(".*[0-9].*")) errors.add("Password must contain a digit");
            }

            return errors.isEmpty() ? ValidationResult.ok() : ValidationResult.fail(errors);
        }

        public static ValidationResult validateOrder(List<OrderItem> items) {
            List<String> errors = new ArrayList<>();

            if (items == null || items.isEmpty()) {
                errors.add("Order must have at least one item");
                return ValidationResult.fail(errors);
            }

            for (int i = 0; i < items.size(); i++) {
                OrderItem item = items.get(i);
                if (item.getQuantity() <= 0) {
                    errors.add("Item " + (i + 1) + ": quantity must be positive");
                }
                if (item.getPrice().compareTo(BigDecimal.ZERO) <= 0) {
                    errors.add("Item " + (i + 1) + ": price must be positive");
                }
            }

            return errors.isEmpty() ? ValidationResult.ok() : ValidationResult.fail(errors);
        }
    }

    // --- Service Orchestrator ---

    private final List<User> users = new ArrayList<>();
    private final List<Order> orders = new ArrayList<>();

    public User createUser(String username, String email, String password, UserRole role) {
        var validation = DataValidator.validateUser(username, email, password);
        if (!validation.valid()) {
            throw new IllegalArgumentException("Validation failed: " + String.join(", ", validation.errors()));
        }

        boolean usernameTaken = users.stream().anyMatch(u -> u.getUsername().equals(username));
        if (usernameTaken) {
            throw new IllegalArgumentException("Username already taken: " + username);
        }

        User user = new User(username, email, password, role);
        users.add(user);
        return user;
    }

    public Order createOrder(String userId, List<OrderItem> items) {
        var validation = DataValidator.validateOrder(items);
        if (!validation.valid()) {
            throw new IllegalArgumentException("Validation failed: " + String.join(", ", validation.errors()));
        }

        boolean userExists = users.stream().anyMatch(u -> u.getId().equals(userId) && u.isActive());
        if (!userExists) {
            throw new IllegalArgumentException("Active user not found: " + userId);
        }

        Order order = new Order(userId, items);
        orders.add(order);
        return order;
    }

    public Map<OrderStatus, List<Order>> getOrdersByStatus() {
        return orders.stream().collect(Collectors.groupingBy(Order::getStatus));
    }

    public Map<String, BigDecimal> getUserOrderTotals() {
        return orders.stream()
                .collect(Collectors.groupingBy(
                        Order::getUserId,
                        Collectors.reducing(BigDecimal.ZERO, Order::getTotal, BigDecimal::add)
                ));
    }

    public List<Order> getTopOrders(int limit) {
        return orders.stream()
                .sorted(Comparator.comparing(Order::getTotal).reversed())
                .limit(limit)
                .collect(Collectors.toList());
    }

    public Optional<User> findUserByUsername(String username) {
        return users.stream().filter(u -> u.getUsername().equals(username)).findFirst();
    }

    // --- Main ---

    public static void main(String[] args) {
        DataService service = new DataService();

        System.out.println("=== Data Service Demo ===\n");

        // Create users
        User admin = service.createUser("admin", "admin@example.com", "Admin123!", UserRole.ADMIN);
        User alice = service.createUser("alice", "alice@example.com", "Alice456!", UserRole.USER);
        User bob = service.createUser("bob", "bob@example.com", "Bobby789!", UserRole.USER);

        System.out.println("Created users:");
        for (User u : service.users) {
            System.out.println("  " + u + " (can manage: " + u.getRole().canManageUsers() + ")");
        }

        // Create orders
        Order order1 = service.createOrder(alice.getId(), List.of(
                new OrderItem("P001", "Laptop", 1, new BigDecimal("999.99")),
                new OrderItem("P002", "Mouse", 2, new BigDecimal("29.99"))
        ));

        Order order2 = service.createOrder(bob.getId(), List.of(
                new OrderItem("P003", "Keyboard", 1, new BigDecimal("79.99")),
                new OrderItem("P004", "Monitor", 1, new BigDecimal("449.99")),
                new OrderItem("P005", "USB Cable", 3, new BigDecimal("9.99"))
        ));

        Order order3 = service.createOrder(alice.getId(), List.of(
                new OrderItem("P006", "Headphones", 1, new BigDecimal("149.99"))
        ));

        System.out.println("\nCreated orders:");
        for (Order o : service.orders) {
            System.out.println("  " + o);
            for (OrderItem item : o.getItems()) {
                System.out.println("    - " + item);
            }
        }

        // Transition order status
        order1.transitionTo(OrderStatus.CONFIRMED);
        order1.transitionTo(OrderStatus.PROCESSING);
        System.out.println("\nOrder 1 status: " + order1.getStatus());

        // Aggregations
        System.out.println("\nTop orders:");
        for (Order o : service.getTopOrders(2)) {
            System.out.printf("  %s: $%s%n", o.getId().substring(0, 8), o.getTotal());
        }

        System.out.println("\nUser order totals:");
        service.getUserOrderTotals().forEach((userId, total) -> {
            String username = service.users.stream()
                    .filter(u -> u.getId().equals(userId))
                    .map(User::getUsername)
                    .findFirst()
                    .orElse("unknown");
            System.out.printf("  %s: $%s%n", username, total);
        });

        // Validation demo
        var badValidation = DataValidator.validateUser("ab", "not-an-email", "short");
        System.out.println("\nValidation errors: " + badValidation.errors());
    }
}
