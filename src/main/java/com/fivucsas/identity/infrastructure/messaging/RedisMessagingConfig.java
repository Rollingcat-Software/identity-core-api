package com.fivucsas.identity.infrastructure.messaging;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.listener.RedisMessageListenerContainer;
import org.springframework.data.redis.serializer.StringRedisSerializer;

import jakarta.annotation.PostConstruct;

/**
 * Redis messaging configuration for event-driven communication.
 *
 * <p>This configuration class sets up Redis infrastructure for pub/sub messaging
 * between the identity-core-api and biometric-processor services.
 *
 * <p><strong>Components Configured:</strong>
 * <ul>
 *   <li>Redis connection factory (Lettuce-based)</li>
 *   <li>Redis template for operations</li>
 *   <li>Message listener container for subscriptions</li>
 *   <li>Event bus and listener beans</li>
 * </ul>
 *
 * <p><strong>Configuration Properties:</strong>
 * <pre>
 * redis.host        - Redis server hostname (default: localhost)
 * redis.port        - Redis server port (default: 6379)
 * redis.password    - Redis authentication password (optional)
 * redis.database    - Redis database index (default: 0)
 * </pre>
 *
 * @author FIVUCSAS Team
 * @version 1.0
 * @since 2025
 */
@Configuration
public class RedisMessagingConfig {

    private static final Logger logger = LoggerFactory.getLogger(RedisMessagingConfig.class);

    @Value("${redis.host:localhost}")
    private String redisHost;

    @Value("${redis.port:6379}")
    private int redisPort;

    @Value("${redis.password:}")
    private String redisPassword;

    @Value("${redis.database:0}")
    private int redisDatabase;

    @Value("${redis.event-bus.enabled:true}")
    private boolean eventBusEnabled;

    /**
     * Creates Redis connection factory using Lettuce.
     *
     * <p>Lettuce is preferred over Jedis for its async and reactive capabilities.
     *
     * @return Redis connection factory
     */
    @Bean
    public RedisConnectionFactory redisConnectionFactory() {
        RedisStandaloneConfiguration config = new RedisStandaloneConfiguration();
        config.setHostName(redisHost);
        config.setPort(redisPort);
        config.setDatabase(redisDatabase);

        if (redisPassword != null && !redisPassword.trim().isEmpty()) {
            config.setPassword(redisPassword);
        }

        logger.info(
                "Configuring Redis connection: host={}, port={}, database={}",
                redisHost,
                redisPort,
                redisDatabase
        );

        return new LettuceConnectionFactory(config);
    }

    /**
     * Creates RedisTemplate for Redis operations.
     *
     * <p>Configured with String serializers for both keys and values
     * to ensure compatibility with the Python biometric-processor.
     *
     * @param connectionFactory Redis connection factory
     * @return Configured RedisTemplate
     */
    @Bean
    public RedisTemplate<String, String> redisTemplate(RedisConnectionFactory connectionFactory) {
        RedisTemplate<String, String> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);

        // Use String serializers for compatibility
        StringRedisSerializer stringSerializer = new StringRedisSerializer();
        template.setKeySerializer(stringSerializer);
        template.setValueSerializer(stringSerializer);
        template.setHashKeySerializer(stringSerializer);
        template.setHashValueSerializer(stringSerializer);

        template.afterPropertiesSet();

        logger.info("RedisTemplate configured with String serializers");
        return template;
    }

    /**
     * Creates Redis message listener container for pub/sub.
     *
     * <p>This container manages subscriptions and dispatches messages
     * to registered listeners.
     *
     * @param connectionFactory Redis connection factory
     * @return Message listener container
     */
    @Bean
    public RedisMessageListenerContainer redisMessageListenerContainer(
            RedisConnectionFactory connectionFactory) {
        RedisMessageListenerContainer container = new RedisMessageListenerContainer();
        container.setConnectionFactory(connectionFactory);

        logger.info("RedisMessageListenerContainer configured");
        return container;
    }

    /**
     * Creates ObjectMapper for JSON serialization.
     * Configured to handle Java 8 date/time types (Instant, LocalDateTime, etc.).
     *
     * @return Jackson ObjectMapper
     */
    @Bean
    public ObjectMapper objectMapper() {
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.registerModule(new JavaTimeModule());
        objectMapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        return objectMapper;
    }

    /**
     * Creates RedisEventBus bean.
     *
     * @param redisTemplate Redis operations template
     * @param messageListenerContainer Message listener container
     * @param objectMapper JSON object mapper
     * @return RedisEventBus instance
     */
    @Bean
    public RedisEventBus redisEventBus(
            RedisTemplate<String, String> redisTemplate,
            RedisMessageListenerContainer messageListenerContainer,
            ObjectMapper objectMapper) {
        return new RedisEventBus(redisTemplate, messageListenerContainer, objectMapper);
    }

    /**
     * Creates BiometricEventListener bean.
     *
     * @return BiometricEventListener instance
     */
    @Bean
    public BiometricEventListener biometricEventListener() {
        return new BiometricEventListener();
    }

    /**
     * Creates BiometricEventPublisher bean.
     *
     * @param redisEventBus Redis event bus
     * @return BiometricEventPublisher instance
     */
    @Bean
    public BiometricEventPublisher biometricEventPublisher(RedisEventBus redisEventBus) {
        return new BiometricEventPublisher(redisEventBus);
    }

    /**
     * Initializes event bus subscriptions.
     *
     * <p>Subscribes to biometric event channels when the application starts.
     */
    @PostConstruct
    public void initializeEventBusSubscriptions() {
        if (!eventBusEnabled) {
            logger.warn("Event bus is disabled in configuration");
            return;
        }

        logger.info("Initializing event bus subscriptions...");

        // Subscribe to biometric processor events
        try {
            RedisEventBus eventBus = redisEventBus(
                    redisTemplate(redisConnectionFactory()),
                    redisMessageListenerContainer(redisConnectionFactory()),
                    objectMapper()
            );
            BiometricEventListener listener = biometricEventListener();

            // Subscribe to enrollment events
            eventBus.subscribe(CHANNEL_ENROLLMENT, listener);

            // Subscribe to verification events
            eventBus.subscribe(CHANNEL_VERIFICATION, listener);

            // Subscribe to liveness check events
            eventBus.subscribe(CHANNEL_LIVENESS, listener);

            // Subscribe to quality assessment events
            eventBus.subscribe(CHANNEL_QUALITY, listener);

            logger.info("Event bus subscriptions initialized successfully");

        } catch (Exception e) {
            logger.error("Failed to initialize event bus subscriptions: {}", e.getMessage(), e);
        }
    }

    // Channel names for subscriptions
    private static final String CHANNEL_ENROLLMENT = "biometric.enrollment";
    private static final String CHANNEL_VERIFICATION = "biometric.verification";
    private static final String CHANNEL_LIVENESS = "biometric.liveness";
    private static final String CHANNEL_QUALITY = "biometric.quality";
}
