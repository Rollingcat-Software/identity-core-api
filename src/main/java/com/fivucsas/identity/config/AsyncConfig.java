package com.fivucsas.identity.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;

/**
 * Configuration for asynchronous processing.
 * Enables @Async annotation support for audit logging and email sending.
 */
@Configuration
@EnableAsync
public class AsyncConfig {
}
