package com.fivucsas.identity.config;

import net.javacrumbs.shedlock.core.LockProvider;
import net.javacrumbs.shedlock.provider.jdbctemplate.JdbcTemplateLockProvider;
import net.javacrumbs.shedlock.spring.annotation.EnableSchedulerLock;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;

import javax.sql.DataSource;

/**
 * Wires ShedLock into the Spring context so {@code @SchedulerLock}-annotated
 * methods take a row-level lease in {@code shedlock} (see V51 migration)
 * before executing.
 *
 * <p>Without this, multiple replicas of identity-core-api would each run
 * scheduled jobs (e.g. {@link com.fivucsas.identity.application.service.SoftDeletePurgeJob}),
 * causing duplicate work, transaction contention, and — for purge — race
 * conditions on the cascade delete window.</p>
 *
 * <p>The default lock-time bounds set on each annotated method
 * ({@code lockAtMostFor} / {@code lockAtLeastFor}) cap the impact of a stuck
 * or crashed instance.</p>
 */
@Configuration
@EnableSchedulerLock(defaultLockAtMostFor = "PT30M")
public class ShedLockConfig {

    @Bean
    public LockProvider lockProvider(DataSource dataSource) {
        return new JdbcTemplateLockProvider(
                JdbcTemplateLockProvider.Configuration.builder()
                        .withJdbcTemplate(new JdbcTemplate(dataSource))
                        .usingDbTime() // use DB clock to avoid replica clock-skew false-locks
                        .build()
        );
    }
}
