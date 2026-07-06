/**
 * Test Scenario 06: Full Spring Boot Microservice
 * Difficulty: Impossible (~800 LOC)
 *
 * Tests:
 * - Spring Boot annotations (@SpringBootApplication, @Service, @RestController, etc.)
 * - JPA entity relationships (@Entity, @ManyToMany, @OneToMany, @JoinTable)
 * - Spring Data JPA repository with custom @Query
 * - @Transactional and @Cacheable service layer
 * - RESTful controller with @Valid, ResponseEntity, pagination
 * - @ControllerAdvice global exception handling
 * - Spring Security with @EnableWebSecurity and JWT authentication
 * - JWT token generation and validation
 * - Swagger/OpenAPI configuration
 * - DTO pattern with mapper
 * - Specification pattern for dynamic queries
 * - Lombok annotations (@Data, @Builder, @Slf4j, @RequiredArgsConstructor)
 * - javax.validation annotations (@NotBlank, @Size, @Email, @Positive)
 * - Pagination and sorting with Pageable
 * - ResponseEntity with HTTP status codes
 * - Custom exceptions hierarchy
 *
 * Expected Go mappings:
 * - @SpringBootApplication    -> main() with router setup
 * - @Entity                   -> struct + GORM/sqlc model
 * - @ManyToMany               -> junction table
 * - JpaRepository             -> repository interface + implementation
 * - @Service                  -> service struct
 * - @RestController           -> http.Handler or gin/chi handlers
 * - @ControllerAdvice         -> middleware error handler
 * - Spring Security           -> middleware chain
 * - JWT                       -> golang-jwt
 * - @Cacheable                -> in-memory cache or groupcache
 * - ResponseEntity            -> (data, statusCode, error)
 * - Pageable                  -> offset/limit parameters
 * - Specification             -> query builder
 * - Lombok @Data              -> struct with exported fields
 * - javax.validation          -> validation library or manual checks
 */

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Predicate;
import java.util.stream.Collectors;

public class Application {

    // =====================================================
    // Domain Exceptions
    // =====================================================

    public static class ResourceNotFoundException extends RuntimeException {
        private final String resourceName;
        private final String fieldName;
        private final Object fieldValue;

        public ResourceNotFoundException(String resourceName, String fieldName, Object fieldValue) {
            super(String.format("%s not found with %s: '%s'", resourceName, fieldName, fieldValue));
            this.resourceName = resourceName;
            this.fieldName = fieldName;
            this.fieldValue = fieldValue;
        }

        public String getResourceName() { return resourceName; }
        public String getFieldName() { return fieldName; }
        public Object getFieldValue() { return fieldValue; }
    }

    public static class BusinessException extends RuntimeException {
        private final String errorCode;

        public BusinessException(String errorCode, String message) {
            super(message);
            this.errorCode = errorCode;
        }

        public String getErrorCode() { return errorCode; }
    }

    public static class UnauthorizedException extends RuntimeException {
        public UnauthorizedException(String message) {
            super(message);
        }
    }

    // =====================================================
    // Entity: Category
    // =====================================================

    // @Entity @Table(name = "categories")
    // @Data @Builder @NoArgsConstructor @AllArgsConstructor
    public static class Category {
        // @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
        private Long id;

        // @NotBlank @Size(min = 2, max = 100)
        // @Column(nullable = false, unique = true)
        private String name;

        // @Size(max = 500)
        private String description;

        // @ManyToMany(mappedBy = "categories")
        private Set<Product> products = new HashSet<>();

        private boolean active = true;
        private LocalDateTime createdAt;
        private LocalDateTime updatedAt;

        public Category(String name, String description) {
            this.name = name;
            this.description = description;
            this.createdAt = LocalDateTime.now();
            this.updatedAt = LocalDateTime.now();
        }

        public Long getId() { return id; }
        public void setId(Long id) { this.id = id; }
        public String getName() { return name; }
        public void setName(String name) { this.name = name; this.updatedAt = LocalDateTime.now(); }
        public String getDescription() { return description; }
        public Set<Product> getProducts() { return products; }
        public boolean isActive() { return active; }
        public void setActive(boolean active) { this.active = active; }
    }

    // =====================================================
    // Entity: Product
    // =====================================================

    public enum ProductStatus { ACTIVE, INACTIVE, DISCONTINUED, OUT_OF_STOCK }

    // @Entity @Table(name = "products")
    // @Data @Builder @NoArgsConstructor @AllArgsConstructor
    public static class Product {
        // @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
        private Long id;

        // @NotBlank @Size(min = 2, max = 200)
        // @Column(nullable = false)
        private String name;

        // @Size(max = 2000)
        private String description;

        // @NotNull @Positive
        // @Column(nullable = false, precision = 10, scale = 2)
        private BigDecimal price;

        // @NotNull @PositiveOrZero
        private Integer stockQuantity;

        // @NotBlank
        private String sku;

        // @Enumerated(EnumType.STRING)
        private ProductStatus status;

        // @ManyToMany
        // @JoinTable(name = "product_categories",
        //     joinColumns = @JoinColumn(name = "product_id"),
        //     inverseJoinColumns = @JoinColumn(name = "category_id"))
        private Set<Category> categories = new HashSet<>();

        private String imageUrl;
        private Double weight;
        private LocalDateTime createdAt;
        private LocalDateTime updatedAt;

        public Product(String name, String description, BigDecimal price, Integer stockQuantity, String sku) {
            this.name = name;
            this.description = description;
            this.price = price;
            this.stockQuantity = stockQuantity;
            this.sku = sku;
            this.status = ProductStatus.ACTIVE;
            this.createdAt = LocalDateTime.now();
            this.updatedAt = LocalDateTime.now();
        }

        public Long getId() { return id; }
        public void setId(Long id) { this.id = id; }
        public String getName() { return name; }
        public void setName(String name) { this.name = name; this.updatedAt = LocalDateTime.now(); }
        public String getDescription() { return description; }
        public void setDescription(String d) { this.description = d; this.updatedAt = LocalDateTime.now(); }
        public BigDecimal getPrice() { return price; }
        public void setPrice(BigDecimal p) { this.price = p; this.updatedAt = LocalDateTime.now(); }
        public Integer getStockQuantity() { return stockQuantity; }
        public void setStockQuantity(Integer q) { this.stockQuantity = q; this.updatedAt = LocalDateTime.now(); }
        public String getSku() { return sku; }
        public ProductStatus getStatus() { return status; }
        public void setStatus(ProductStatus s) { this.status = s; this.updatedAt = LocalDateTime.now(); }
        public Set<Category> getCategories() { return categories; }
        public void addCategory(Category c) { categories.add(c); c.getProducts().add(this); }
        public void removeCategory(Category c) { categories.remove(c); c.getProducts().remove(this); }
        public String getImageUrl() { return imageUrl; }
        public void setImageUrl(String url) { this.imageUrl = url; }
        public Double getWeight() { return weight; }
        public void setWeight(Double w) { this.weight = w; }
        public LocalDateTime getCreatedAt() { return createdAt; }
        public LocalDateTime getUpdatedAt() { return updatedAt; }
    }

    // =====================================================
    // DTOs
    // =====================================================

    // @Data @Builder
    public record ProductDTO(
            Long id,
            String name,
            String description,
            BigDecimal price,
            Integer stockQuantity,
            String sku,
            ProductStatus status,
            List<String> categoryNames,
            String imageUrl,
            Double weight,
            LocalDateTime createdAt
    ) {}

    // @Data
    public record CreateProductRequest(
            // @NotBlank @Size(min = 2, max = 200)
            String name,
            // @Size(max = 2000)
            String description,
            // @NotNull @Positive
            BigDecimal price,
            // @NotNull @PositiveOrZero
            Integer stockQuantity,
            // @NotBlank
            String sku,
            List<Long> categoryIds,
            String imageUrl,
            Double weight
    ) {}

    // @Data
    public record UpdateProductRequest(
            String name,
            String description,
            BigDecimal price,
            Integer stockQuantity,
            ProductStatus status,
            List<Long> categoryIds,
            String imageUrl,
            Double weight
    ) {}

    public record PageResponse<T>(List<T> content, int page, int size, long totalElements, int totalPages) {}

    public record ErrorResponse(int status, String error, String message, LocalDateTime timestamp) {}

    // =====================================================
    // Product Search Criteria (Specification Pattern)
    // =====================================================

    public static class ProductSearchCriteria {
        private String nameContains;
        private BigDecimal minPrice;
        private BigDecimal maxPrice;
        private ProductStatus status;
        private String categoryName;
        private Boolean inStock;

        public ProductSearchCriteria() {}

        public ProductSearchCriteria nameContains(String name) { this.nameContains = name; return this; }
        public ProductSearchCriteria minPrice(BigDecimal min) { this.minPrice = min; return this; }
        public ProductSearchCriteria maxPrice(BigDecimal max) { this.maxPrice = max; return this; }
        public ProductSearchCriteria status(ProductStatus s) { this.status = s; return this; }
        public ProductSearchCriteria categoryName(String cat) { this.categoryName = cat; return this; }
        public ProductSearchCriteria inStock(Boolean inStock) { this.inStock = inStock; return this; }

        public Predicate<Product> toSpecification() {
            Predicate<Product> spec = p -> true;

            if (nameContains != null && !nameContains.isBlank()) {
                String lower = nameContains.toLowerCase();
                spec = spec.and(p -> p.getName().toLowerCase().contains(lower));
            }
            if (minPrice != null) {
                spec = spec.and(p -> p.getPrice().compareTo(minPrice) >= 0);
            }
            if (maxPrice != null) {
                spec = spec.and(p -> p.getPrice().compareTo(maxPrice) <= 0);
            }
            if (status != null) {
                spec = spec.and(p -> p.getStatus() == status);
            }
            if (categoryName != null) {
                spec = spec.and(p -> p.getCategories().stream()
                        .anyMatch(c -> c.getName().equalsIgnoreCase(categoryName)));
            }
            if (inStock != null && inStock) {
                spec = spec.and(p -> p.getStockQuantity() != null && p.getStockQuantity() > 0);
            }

            return spec;
        }
    }

    // =====================================================
    // Product Mapper
    // =====================================================

    public static class ProductMapper {
        public static ProductDTO toDTO(Product product) {
            List<String> categoryNames = product.getCategories().stream()
                    .map(Category::getName)
                    .sorted()
                    .collect(Collectors.toList());

            return new ProductDTO(
                    product.getId(), product.getName(), product.getDescription(),
                    product.getPrice(), product.getStockQuantity(), product.getSku(),
                    product.getStatus(), categoryNames, product.getImageUrl(),
                    product.getWeight(), product.getCreatedAt()
            );
        }

        public static Product toEntity(CreateProductRequest request) {
            Product product = new Product(
                    request.name(), request.description(),
                    request.price(), request.stockQuantity(), request.sku()
            );
            product.setImageUrl(request.imageUrl());
            product.setWeight(request.weight());
            return product;
        }

        public static void updateEntity(Product product, UpdateProductRequest request) {
            if (request.name() != null) product.setName(request.name());
            if (request.description() != null) product.setDescription(request.description());
            if (request.price() != null) product.setPrice(request.price());
            if (request.stockQuantity() != null) product.setStockQuantity(request.stockQuantity());
            if (request.status() != null) product.setStatus(request.status());
            if (request.imageUrl() != null) product.setImageUrl(request.imageUrl());
            if (request.weight() != null) product.setWeight(request.weight());
        }
    }

    // =====================================================
    // Repository Layer (In-Memory, simulating JPA)
    // =====================================================

    // public interface ProductRepository extends JpaRepository<Product, Long>
    public interface ProductRepository {
        Optional<Product> findById(Long id);
        Optional<Product> findBySku(String sku);
        List<Product> findAll();
        List<Product> findByStatus(ProductStatus status);
        // @Query("SELECT p FROM Product p WHERE LOWER(p.name) LIKE LOWER(CONCAT('%',:name,'%'))")
        List<Product> searchByName(String name);
        // @Query("SELECT p FROM Product p JOIN p.categories c WHERE c.id = :categoryId")
        List<Product> findByCategoryId(Long categoryId);
        Product save(Product product);
        void deleteById(Long id);
        long count();
    }

    public static class InMemoryProductRepository implements ProductRepository {
        private final ConcurrentHashMap<Long, Product> store = new ConcurrentHashMap<>();
        private long nextId = 1;

        @Override
        public Optional<Product> findById(Long id) {
            return Optional.ofNullable(store.get(id));
        }

        @Override
        public Optional<Product> findBySku(String sku) {
            return store.values().stream().filter(p -> p.getSku().equals(sku)).findFirst();
        }

        @Override
        public List<Product> findAll() { return new ArrayList<>(store.values()); }

        @Override
        public List<Product> findByStatus(ProductStatus status) {
            return store.values().stream().filter(p -> p.getStatus() == status).collect(Collectors.toList());
        }

        @Override
        public List<Product> searchByName(String name) {
            String lower = name.toLowerCase();
            return store.values().stream()
                    .filter(p -> p.getName().toLowerCase().contains(lower))
                    .collect(Collectors.toList());
        }

        @Override
        public List<Product> findByCategoryId(Long categoryId) {
            return store.values().stream()
                    .filter(p -> p.getCategories().stream().anyMatch(c -> Objects.equals(c.getId(), categoryId)))
                    .collect(Collectors.toList());
        }

        @Override
        public synchronized Product save(Product product) {
            if (product.getId() == null) {
                product.setId(nextId++);
            }
            store.put(product.getId(), product);
            return product;
        }

        @Override
        public void deleteById(Long id) { store.remove(id); }

        @Override
        public long count() { return store.size(); }
    }

    // =====================================================
    // JWT Token Provider
    // =====================================================

    public static class JwtTokenProvider {
        private final String secretKey;
        private final long expirationMs;
        private final Map<String, TokenInfo> issuedTokens = new ConcurrentHashMap<>();

        public record TokenInfo(String username, String role, long issuedAt, long expiresAt) {}

        public JwtTokenProvider(String secretKey, long expirationMs) {
            this.secretKey = secretKey;
            this.expirationMs = expirationMs;
        }

        public String generateToken(String username, String role) {
            long now = System.currentTimeMillis();
            long expiration = now + expirationMs;

            // Simplified token (production would use JJWT or Nimbus)
            String payload = String.format("{\"sub\":\"%s\",\"role\":\"%s\",\"iat\":%d,\"exp\":%d}",
                    username, role, now, expiration);
            String token = Base64.getEncoder().encodeToString(payload.getBytes());

            issuedTokens.put(token, new TokenInfo(username, role, now, expiration));
            return token;
        }

        public Optional<TokenInfo> validateToken(String token) {
            TokenInfo info = issuedTokens.get(token);
            if (info == null) {
                return Optional.empty();
            }
            if (System.currentTimeMillis() > info.expiresAt()) {
                issuedTokens.remove(token);
                return Optional.empty();
            }
            return Optional.of(info);
        }

        public void invalidateToken(String token) {
            issuedTokens.remove(token);
        }
    }

    // =====================================================
    // Security Filter (simulating Spring Security)
    // =====================================================

    public static class SecurityContext {
        private static final ThreadLocal<AuthenticatedUser> currentUser = new ThreadLocal<>();

        public record AuthenticatedUser(String username, String role) {
            public boolean isAdmin() { return "ADMIN".equals(role); }
        }

        public static void setCurrentUser(AuthenticatedUser user) { currentUser.set(user); }
        public static Optional<AuthenticatedUser> getCurrentUser() { return Optional.ofNullable(currentUser.get()); }
        public static void clear() { currentUser.remove(); }
    }

    public static class JwtAuthenticationFilter {
        private final JwtTokenProvider tokenProvider;

        public JwtAuthenticationFilter(JwtTokenProvider tokenProvider) {
            this.tokenProvider = tokenProvider;
        }

        public boolean authenticate(String authHeader) {
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return false;
            }

            String token = authHeader.substring(7);
            Optional<JwtTokenProvider.TokenInfo> tokenInfo = tokenProvider.validateToken(token);

            if (tokenInfo.isPresent()) {
                JwtTokenProvider.TokenInfo info = tokenInfo.get();
                SecurityContext.setCurrentUser(
                        new SecurityContext.AuthenticatedUser(info.username(), info.role()));
                return true;
            }

            return false;
        }
    }

    // =====================================================
    // Service Layer
    // =====================================================

    // @Service @Slf4j @RequiredArgsConstructor
    public static class ProductService {
        private final ProductRepository repository;
        private final Map<Long, ProductDTO> cache = new ConcurrentHashMap<>();

        public ProductService(ProductRepository repository) {
            this.repository = repository;
        }

        // @Transactional(readOnly = true) @Cacheable("products")
        public ProductDTO getProduct(Long id) {
            ProductDTO cached = cache.get(id);
            if (cached != null) {
                return cached;
            }

            Product product = repository.findById(id)
                    .orElseThrow(() -> new ResourceNotFoundException("Product", "id", id));

            ProductDTO dto = ProductMapper.toDTO(product);
            cache.put(id, dto);
            return dto;
        }

        // @Transactional(readOnly = true)
        public PageResponse<ProductDTO> getProducts(int page, int size) {
            List<Product> all = repository.findAll();
            int totalElements = all.size();
            int totalPages = (int) Math.ceil((double) totalElements / size);
            int fromIndex = Math.min(page * size, totalElements);
            int toIndex = Math.min(fromIndex + size, totalElements);

            List<ProductDTO> content = all.subList(fromIndex, toIndex).stream()
                    .map(ProductMapper::toDTO)
                    .collect(Collectors.toList());

            return new PageResponse<>(content, page, size, totalElements, totalPages);
        }

        // @Transactional(readOnly = true)
        public List<ProductDTO> searchProducts(ProductSearchCriteria criteria) {
            Predicate<Product> spec = criteria.toSpecification();
            return repository.findAll().stream()
                    .filter(spec)
                    .map(ProductMapper::toDTO)
                    .collect(Collectors.toList());
        }

        // @Transactional
        public ProductDTO createProduct(CreateProductRequest request) {
            repository.findBySku(request.sku()).ifPresent(existing -> {
                throw new BusinessException("DUPLICATE_SKU",
                        "Product with SKU '" + request.sku() + "' already exists");
            });

            Product product = ProductMapper.toEntity(request);
            product = repository.save(product);

            ProductDTO dto = ProductMapper.toDTO(product);
            cache.put(product.getId(), dto);
            return dto;
        }

        // @Transactional
        public ProductDTO updateProduct(Long id, UpdateProductRequest request) {
            Product product = repository.findById(id)
                    .orElseThrow(() -> new ResourceNotFoundException("Product", "id", id));

            ProductMapper.updateEntity(product, request);
            product = repository.save(product);

            ProductDTO dto = ProductMapper.toDTO(product);
            cache.put(id, dto);
            return dto;
        }

        // @Transactional
        public void deleteProduct(Long id) {
            if (repository.findById(id).isEmpty()) {
                throw new ResourceNotFoundException("Product", "id", id);
            }
            repository.deleteById(id);
            cache.remove(id);
        }

        public void evictCache() {
            cache.clear();
        }
    }

    // =====================================================
    // Global Exception Handler (@ControllerAdvice)
    // =====================================================

    public static class GlobalExceptionHandler {
        public record HandlerResult(int status, ErrorResponse body) {}

        public HandlerResult handleResourceNotFound(ResourceNotFoundException ex) {
            return new HandlerResult(404, new ErrorResponse(
                    404, "Not Found", ex.getMessage(), LocalDateTime.now()));
        }

        public HandlerResult handleBusinessException(BusinessException ex) {
            return new HandlerResult(409, new ErrorResponse(
                    409, ex.getErrorCode(), ex.getMessage(), LocalDateTime.now()));
        }

        public HandlerResult handleUnauthorized(UnauthorizedException ex) {
            return new HandlerResult(401, new ErrorResponse(
                    401, "Unauthorized", ex.getMessage(), LocalDateTime.now()));
        }

        public HandlerResult handleValidationError(IllegalArgumentException ex) {
            return new HandlerResult(400, new ErrorResponse(
                    400, "Bad Request", ex.getMessage(), LocalDateTime.now()));
        }

        public HandlerResult handleGenericError(Exception ex) {
            return new HandlerResult(500, new ErrorResponse(
                    500, "Internal Server Error", "An unexpected error occurred", LocalDateTime.now()));
        }

        public HandlerResult handle(Exception ex) {
            if (ex instanceof ResourceNotFoundException rnf) return handleResourceNotFound(rnf);
            if (ex instanceof BusinessException be) return handleBusinessException(be);
            if (ex instanceof UnauthorizedException ue) return handleUnauthorized(ue);
            if (ex instanceof IllegalArgumentException iae) return handleValidationError(iae);
            return handleGenericError(ex);
        }
    }

    // =====================================================
    // REST Controller
    // =====================================================

    // @RestController @RequestMapping("/api/v1/products")
    // @RequiredArgsConstructor @Slf4j
    public static class ProductController {
        private final ProductService service;
        private final JwtAuthenticationFilter authFilter;
        private final GlobalExceptionHandler exceptionHandler;

        public ProductController(ProductService service, JwtAuthenticationFilter authFilter) {
            this.service = service;
            this.authFilter = authFilter;
            this.exceptionHandler = new GlobalExceptionHandler();
        }

        // @GetMapping
        public Object getAllProducts(int page, int size, String authHeader) {
            try {
                if (!authFilter.authenticate(authHeader)) {
                    throw new UnauthorizedException("Invalid or missing authentication token");
                }
                if (size <= 0) size = 10;
                if (size > 100) size = 100;
                if (page < 0) page = 0;

                return service.getProducts(page, size);
            } catch (Exception ex) {
                return exceptionHandler.handle(ex);
            } finally {
                SecurityContext.clear();
            }
        }

        // @GetMapping("/{id}")
        public Object getProduct(Long id, String authHeader) {
            try {
                if (!authFilter.authenticate(authHeader)) {
                    throw new UnauthorizedException("Invalid or missing authentication token");
                }
                return service.getProduct(id);
            } catch (Exception ex) {
                return exceptionHandler.handle(ex);
            } finally {
                SecurityContext.clear();
            }
        }

        // @PostMapping
        public Object createProduct(CreateProductRequest request, String authHeader) {
            try {
                if (!authFilter.authenticate(authHeader)) {
                    throw new UnauthorizedException("Invalid or missing authentication token");
                }
                var user = SecurityContext.getCurrentUser()
                        .orElseThrow(() -> new UnauthorizedException("No authenticated user"));
                if (!user.isAdmin()) {
                    throw new UnauthorizedException("Admin role required to create products");
                }

                validateCreateRequest(request);
                return service.createProduct(request);
            } catch (Exception ex) {
                return exceptionHandler.handle(ex);
            } finally {
                SecurityContext.clear();
            }
        }

        // @PutMapping("/{id}")
        public Object updateProduct(Long id, UpdateProductRequest request, String authHeader) {
            try {
                if (!authFilter.authenticate(authHeader)) {
                    throw new UnauthorizedException("Invalid or missing authentication token");
                }
                var user = SecurityContext.getCurrentUser()
                        .orElseThrow(() -> new UnauthorizedException("No authenticated user"));
                if (!user.isAdmin()) {
                    throw new UnauthorizedException("Admin role required to update products");
                }

                return service.updateProduct(id, request);
            } catch (Exception ex) {
                return exceptionHandler.handle(ex);
            } finally {
                SecurityContext.clear();
            }
        }

        // @DeleteMapping("/{id}")
        public Object deleteProduct(Long id, String authHeader) {
            try {
                if (!authFilter.authenticate(authHeader)) {
                    throw new UnauthorizedException("Invalid or missing authentication token");
                }
                var user = SecurityContext.getCurrentUser()
                        .orElseThrow(() -> new UnauthorizedException("No authenticated user"));
                if (!user.isAdmin()) {
                    throw new UnauthorizedException("Admin role required to delete products");
                }

                service.deleteProduct(id);
                return Map.of("message", "Product deleted successfully");
            } catch (Exception ex) {
                return exceptionHandler.handle(ex);
            } finally {
                SecurityContext.clear();
            }
        }

        // @GetMapping("/search")
        public Object searchProducts(String name, BigDecimal minPrice, BigDecimal maxPrice,
                                     String status, Boolean inStock, String authHeader) {
            try {
                if (!authFilter.authenticate(authHeader)) {
                    throw new UnauthorizedException("Invalid or missing authentication token");
                }

                ProductSearchCriteria criteria = new ProductSearchCriteria();
                if (name != null) criteria.nameContains(name);
                if (minPrice != null) criteria.minPrice(minPrice);
                if (maxPrice != null) criteria.maxPrice(maxPrice);
                if (status != null) criteria.status(ProductStatus.valueOf(status));
                if (inStock != null) criteria.inStock(inStock);

                return service.searchProducts(criteria);
            } catch (Exception ex) {
                return exceptionHandler.handle(ex);
            } finally {
                SecurityContext.clear();
            }
        }

        private void validateCreateRequest(CreateProductRequest request) {
            List<String> errors = new ArrayList<>();
            if (request.name() == null || request.name().isBlank()) errors.add("Name is required");
            if (request.name() != null && request.name().length() > 200) errors.add("Name too long (max 200)");
            if (request.price() == null) errors.add("Price is required");
            if (request.price() != null && request.price().compareTo(BigDecimal.ZERO) <= 0) errors.add("Price must be positive");
            if (request.stockQuantity() == null) errors.add("Stock quantity is required");
            if (request.stockQuantity() != null && request.stockQuantity() < 0) errors.add("Stock cannot be negative");
            if (request.sku() == null || request.sku().isBlank()) errors.add("SKU is required");

            if (!errors.isEmpty()) {
                throw new IllegalArgumentException("Validation failed: " + String.join(", ", errors));
            }
        }
    }

    // =====================================================
    // Swagger/OpenAPI Config (simulated)
    // =====================================================

    public static class SwaggerConfig {
        private final String title;
        private final String version;
        private final String description;
        private final Map<String, Object> paths = new HashMap<>();

        public SwaggerConfig(String title, String version, String description) {
            this.title = title;
            this.version = version;
            this.description = description;
        }

        public void addPath(String path, String method, String summary) {
            paths.put(method.toUpperCase() + " " + path, Map.of("summary", summary));
        }

        public Map<String, Object> generateSpec() {
            Map<String, Object> spec = new HashMap<>();
            spec.put("openapi", "3.0.3");
            spec.put("info", Map.of("title", title, "version", version, "description", description));
            spec.put("paths", paths);
            return spec;
        }
    }

    // =====================================================
    // Application Entry Point
    // =====================================================

    // @SpringBootApplication
    public static void main(String[] args) {
        System.out.println("=== Spring Microservice Demo ===\n");

        // Initialize components
        InMemoryProductRepository repository = new InMemoryProductRepository();
        ProductService service = new ProductService(repository);
        JwtTokenProvider tokenProvider = new JwtTokenProvider("secret-key-256-bits-long!!", 3600000);
        JwtAuthenticationFilter authFilter = new JwtAuthenticationFilter(tokenProvider);
        ProductController controller = new ProductController(service, authFilter);

        // Configure Swagger
        SwaggerConfig swagger = new SwaggerConfig("Product API", "1.0", "Product management microservice");
        swagger.addPath("/api/v1/products", "GET", "List all products");
        swagger.addPath("/api/v1/products/{id}", "GET", "Get product by ID");
        swagger.addPath("/api/v1/products", "POST", "Create a product");
        swagger.addPath("/api/v1/products/{id}", "PUT", "Update a product");
        swagger.addPath("/api/v1/products/{id}", "DELETE", "Delete a product");
        swagger.addPath("/api/v1/products/search", "GET", "Search products");

        // Generate tokens
        String adminToken = "Bearer " + tokenProvider.generateToken("admin", "ADMIN");
        String userToken = "Bearer " + tokenProvider.generateToken("viewer", "USER");

        System.out.println("Admin token generated");
        System.out.println("User token generated\n");

        // Create products (as admin)
        System.out.println("--- Creating products ---");
        var p1 = controller.createProduct(
                new CreateProductRequest("Laptop Pro", "High-end laptop", new BigDecimal("1499.99"),
                        50, "LAP-001", null, "https://img.example.com/laptop.jpg", 2.1),
                adminToken);
        System.out.println("Created: " + p1);

        var p2 = controller.createProduct(
                new CreateProductRequest("Wireless Mouse", "Ergonomic mouse", new BigDecimal("29.99"),
                        200, "MOU-001", null, null, 0.1),
                adminToken);
        System.out.println("Created: " + p2);

        var p3 = controller.createProduct(
                new CreateProductRequest("Mechanical Keyboard", "Cherry MX switches", new BigDecimal("149.99"),
                        75, "KEY-001", null, null, 0.8),
                adminToken);
        System.out.println("Created: " + p3);

        var p4 = controller.createProduct(
                new CreateProductRequest("USB-C Hub", "7-in-1 hub", new BigDecimal("49.99"),
                        0, "HUB-001", null, null, 0.15),
                adminToken);
        System.out.println("Created: " + p4);

        // Try creating with user token (should fail)
        System.out.println("\n--- Access control test ---");
        var unauthorized = controller.createProduct(
                new CreateProductRequest("Test", "test", new BigDecimal("10"), 1, "TST-001", null, null, null),
                userToken);
        System.out.println("User create attempt: " + unauthorized);

        // Try with no token
        var noAuth = controller.getProduct(1L, null);
        System.out.println("No auth attempt: " + noAuth);

        // List all products (as user)
        System.out.println("\n--- Listing products ---");
        var allProducts = controller.getAllProducts(0, 10, userToken);
        System.out.println("All products: " + allProducts);

        // Get single product
        var single = controller.getProduct(1L, userToken);
        System.out.println("\nProduct 1: " + single);

        // Search products
        System.out.println("\n--- Searching products ---");
        var searchResult = controller.searchProducts(
                "mouse", null, null, null, true, userToken);
        System.out.println("Search 'mouse': " + searchResult);

        var priceSearch = controller.searchProducts(
                null, new BigDecimal("30"), new BigDecimal("200"), null, null, userToken);
        System.out.println("Price $30-$200: " + priceSearch);

        // Update product (as admin)
        System.out.println("\n--- Updating product ---");
        var updated = controller.updateProduct(1L,
                new UpdateProductRequest("Laptop Pro Max", null, new BigDecimal("1699.99"),
                        45, null, null, null, null),
                adminToken);
        System.out.println("Updated: " + updated);

        // Delete product (as admin)
        System.out.println("\n--- Deleting product ---");
        var deleted = controller.deleteProduct(4L, adminToken);
        System.out.println("Deleted: " + deleted);

        // Try to get deleted product
        var notFound = controller.getProduct(4L, userToken);
        System.out.println("Get deleted: " + notFound);

        // Duplicate SKU test
        System.out.println("\n--- Duplicate SKU test ---");
        var duplicate = controller.createProduct(
                new CreateProductRequest("Another Laptop", "Copy", new BigDecimal("999"),
                        10, "LAP-001", null, null, null),
                adminToken);
        System.out.println("Duplicate SKU: " + duplicate);

        // Validation error test
        System.out.println("\n--- Validation test ---");
        var invalid = controller.createProduct(
                new CreateProductRequest("", null, new BigDecimal("-5"),
                        -1, "", null, null, null),
                adminToken);
        System.out.println("Invalid product: " + invalid);

        // API spec
        System.out.println("\n--- API Specification ---");
        var spec = swagger.generateSpec();
        System.out.println("OpenAPI: " + spec.get("openapi"));
        System.out.println("Title: " + ((Map<?, ?>) spec.get("info")).get("title"));
        System.out.println("Endpoints: " + ((Map<?, ?>) spec.get("paths")).size());

        System.out.println("\nMicroservice demo complete.");
    }
}
