package com.fivucsas.identity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.task.TaskExecutor;
import org.springframework.scheduling.annotation.AsyncConfigurer;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import java.util.concurrent.Executor;
import java.util.concurrent.ThreadPoolExecutor;

/**
 * Configuration for asynchronous processing.
 * Enables @Async annotation support for audit logging and email sending.
 *
 * <p>Defines a bounded {@link ThreadPoolTaskExecutor} as the default executor for
 * {@code @Async} dispatch. Without an explicit executor, Spring falls back to a
 * SimpleAsyncTaskExecutor that creates an unbounded number of threads — under
 * load this exhausts the JVM. The pool below caps at 20 worker threads with a
 * 100-task queue; tasks beyond that fall back to {@link ThreadPoolExecutor.CallerRunsPolicy}
 * so back-pressure surfaces in the calling thread rather than silently
 * dropping audit events.</p>
 */
@Configuration
@EnableAsync
public class AsyncConfig implements AsyncConfigurer {

    @Bean(name = "taskExecutor")
    public TaskExecutor taskExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(10);
        executor.setMaxPoolSize(20);
        executor.setQueueCapacity(100);
        executor.setThreadNamePrefix("async-");
        executor.setRejectedExecutionHandler(new ThreadPoolExecutor.CallerRunsPolicy());
        executor.initialize();
        return executor;
    }

    @Override
    public Executor getAsyncExecutor() {
        return taskExecutor();
    }
}
