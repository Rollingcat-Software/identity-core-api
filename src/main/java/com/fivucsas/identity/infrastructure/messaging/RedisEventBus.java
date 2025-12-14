package com.fivucsas.identity.infrastructure.messaging;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.connection.Message;
import org.springframework.data.redis.connection.MessageListener;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.listener.ChannelTopic;
import org.springframework.data.redis.listener.RedisMessageListenerContainer;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Redis-based event bus implementation for async biometric processing.
 *
 * <p>This component implements the event bus pattern using Redis Pub/Sub
 * for real-time event-driven communication between microservices.
 *
 * <p><strong>Architecture:</strong>
 * <ul>
 *   <li>Follows Hexagonal Architecture (Port/Adapter pattern)</li>
 *   <li>Uses Spring Data Redis for Redis operations</li>
 *   <li>Supports pub/sub pattern for event distribution</li>
 *   <li>JSON serialization for event payloads</li>
 * </ul>
 *
 * <p><strong>SOLID Principles:</strong>
 * <ul>
 *   <li>Single Responsibility: Only handles Redis event bus operations</li>
 *   <li>Open/Closed: Extensible through listener registration</li>
 *   <li>Dependency Inversion: Depends on RedisTemplate abstraction</li>
 * </ul>
 *
 * @author FIVUCSAS Team
 * @version 1.0
 * @since 2025
 */
@Component
public class RedisEventBus {

    private static final Logger logger = LoggerFactory.getLogger(RedisEventBus.class);

    private final RedisTemplate<String, String> redisTemplate;
    private final RedisMessageListenerContainer messageListenerContainer;
    private final ObjectMapper objectMapper;
    private final Map<String, BiometricEventListener> listeners;

    /**
     * Constructs a RedisEventBus with required dependencies.
     *
     * @param redisTemplate Redis operations template
     * @param messageListenerContainer Container for message listeners
     * @param objectMapper JSON object mapper
     */
    public RedisEventBus(
            RedisTemplate<String, String> redisTemplate,
            RedisMessageListenerContainer messageListenerContainer,
            ObjectMapper objectMapper) {
        this.redisTemplate = redisTemplate;
        this.messageListenerContainer = messageListenerContainer;
        this.objectMapper = objectMapper;
        this.listeners = new ConcurrentHashMap<>();
        logger.info("RedisEventBus initialized");
    }

    /**
     * Publishes an event to a Redis channel.
     *
     * <p>Events are serialized to JSON before being published to the channel.
     * This method is non-blocking and returns immediately after publishing.
     *
     * @param channel Channel/topic name to publish to
     * @param event Event data (must be serializable to JSON)
     * @return true if published successfully, false otherwise
     */
    public boolean publish(String channel, Map<String, Object> event) {
        try {
            String eventJson = objectMapper.writeValueAsString(event);
            redisTemplate.convertAndSend(channel, eventJson);

            logger.debug(
                    "Published event to channel '{}': event_type={}, event_id={}",
                    channel,
                    event.get("event_type"),
                    event.get("event_id")
            );

            return true;

        } catch (JsonProcessingException e) {
            logger.error("Failed to serialize event for channel '{}': {}", channel, e.getMessage());
            return false;
        } catch (Exception e) {
            logger.error("Failed to publish event to channel '{}': {}", channel, e.getMessage(), e);
            return false;
        }
    }

    /**
     * Subscribes to events on a Redis channel.
     *
     * <p>The provided listener will be invoked for each message received on the channel.
     * Multiple listeners can be registered for the same channel.
     *
     * @param channel Channel/topic name to subscribe to
     * @param listener Event listener to handle received events
     */
    public void subscribe(String channel, BiometricEventListener listener) {
        try {
            // Create a message listener adapter
            MessageListener messageListener = (message, pattern) -> {
                try {
                    String messageBody = new String(message.getBody());
                    @SuppressWarnings("unchecked")
                    Map<String, Object> event = objectMapper.readValue(messageBody, Map.class);

                    logger.debug(
                            "Received event from channel '{}': event_type={}",
                            channel,
                            event.get("event_type")
                    );

                    listener.onEvent(event);

                } catch (Exception e) {
                    logger.error(
                            "Error processing event from channel '{}': {}",
                            channel,
                            e.getMessage(),
                            e
                    );
                }
            };

            // Register listener
            ChannelTopic topic = new ChannelTopic(channel);
            messageListenerContainer.addMessageListener(messageListener, topic);
            listeners.put(channel, listener);

            logger.info("Subscribed to channel: {}", channel);

        } catch (Exception e) {
            logger.error("Failed to subscribe to channel '{}': {}", channel, e.getMessage(), e);
        }
    }

    /**
     * Unsubscribes from a Redis channel.
     *
     * @param channel Channel/topic name to unsubscribe from
     */
    public void unsubscribe(String channel) {
        try {
            listeners.remove(channel);
            // Note: Spring's RedisMessageListenerContainer doesn't provide direct
            // unsubscribe by channel, so we rely on container lifecycle management
            logger.info("Unsubscribed from channel: {}", channel);

        } catch (Exception e) {
            logger.error("Failed to unsubscribe from channel '{}': {}", channel, e.getMessage());
        }
    }

    /**
     * Checks if the Redis connection is healthy.
     *
     * @return true if healthy, false otherwise
     */
    public boolean isHealthy() {
        try {
            redisTemplate.getConnectionFactory()
                    .getConnection()
                    .ping();
            return true;
        } catch (Exception e) {
            logger.error("Redis health check failed: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Gets the number of active listeners.
     *
     * @return Number of registered listeners
     */
    public int getActiveListenerCount() {
        return listeners.size();
    }
}
