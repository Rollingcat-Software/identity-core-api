# FIVUCSAS Identity Core API - Dockerfile
# Multi-stage build for Spring Boot 3.4 with Java 21

# =============================================================================
# Stage 1: Build
# =============================================================================
FROM maven:3.9.9-eclipse-temurin-21-alpine AS builder

WORKDIR /app

# Copy pom.xml first for dependency caching
COPY pom.xml .

# Pre-fetch dependencies into a cached layer; subsequent src changes don't
# redownload them. Plugin resolution may still hit the network on the
# package step, so we deliberately avoid `--offline` to stay robust (P3.7).
RUN mvn dependency:go-offline -B

# Copy source code
COPY src ./src

# Build the application. -Dmaven.test.skip=true skips both compile and run
# of tests (faster than -DskipTests, which still compiles them).
RUN mvn package -Dmaven.test.skip=true -B

# =============================================================================
# Stage 2: Runtime
# =============================================================================
FROM eclipse-temurin:21-jre-alpine

# Install curl for health checks
RUN apk add --no-cache curl

# Add non-root user for security
RUN addgroup -S spring && adduser -S spring -G spring

WORKDIR /app

# Copy the built JAR from builder stage
COPY --from=builder /app/target/*.jar app.jar

# Set ownership
RUN chown -R spring:spring /app

# Switch to non-root user
USER spring

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8080/actuator/health || exit 1

# JVM options for containers.
#
# -Xms/-Xmx are deliberately omitted: the prior `-Xmx512m` silently
# overrode `MaxRAMPercentage` and capped the heap at 512 MB even though
# the production container runs with a 2 GiB limit. Removing the
# explicit -Xmx restores the percentage-based sizing — at 75% of 2 GiB
# the heap is ~1.5 GB, ~3× the prior cap, which removes the most common
# young-GC pause class on /auth/login and /users.
#
# UseContainerSupport is the default on Java 21 but kept explicit for
# clarity. ExitOnOutOfMemoryError + heap-dump-on-OOM produce a
# diagnosable artifact instead of a half-alive container.
ENV JAVA_OPTS="-XX:+UseContainerSupport -XX:MaxRAMPercentage=75.0 -XX:InitialRAMPercentage=50.0 -XX:+UseG1GC -XX:MaxGCPauseMillis=200 -XX:+ExitOnOutOfMemoryError -XX:+HeapDumpOnOutOfMemoryError -XX:HeapDumpPath=/tmp/heapdump.hprof"

# Run the application
ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar app.jar"]
