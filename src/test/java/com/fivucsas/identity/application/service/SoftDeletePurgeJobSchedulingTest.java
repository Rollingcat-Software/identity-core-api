package com.fivucsas.identity.application.service;

import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Static-shape regression for {@link SoftDeletePurgeJob} (T2-E,
 * INVESTIGATION_MASTER_2026-05-07 P1):
 *
 * <ol>
 *   <li>The scheduled entry point ({@code runScheduled}) must keep its
 *       {@link Scheduled @Scheduled(cron = "0 30 3 * * *")} annotation, otherwise
 *       the GDPR Art. 17 / KVKK hard-purge silently stops running.</li>
 *   <li>The same method must keep its {@link SchedulerLock} annotation so two
 *       JVM replicas do not race the purge transaction.</li>
 *   <li>The {@code enabled} field must keep its
 *       {@code @Value("${app.purge.softDelete.enabled:false}")} wiring — that
 *       placeholder is how {@code application-prod.yml}'s default-on flag
 *       reaches the bean. If the placeholder is renamed, the prod default
 *       silently regresses to {@code false}.</li>
 * </ol>
 *
 * <p>This is a pure-reflection contract test — no Spring context, no DB. It
 * complements {@link SoftDeletePurgeJobTest} (which covers runtime semantics)
 * by guarding the metadata that the scheduler + property binder rely on.
 */
@DisplayName("SoftDeletePurgeJob — scheduling + property-binding contract")
class SoftDeletePurgeJobSchedulingTest {

    @Test
    @DisplayName("runScheduled() carries @Scheduled(cron = \"0 30 3 * * *\")")
    void runScheduledHasCorrectCron() throws NoSuchMethodException {
        Method method = SoftDeletePurgeJob.class.getMethod("runScheduled");
        Scheduled scheduled = method.getAnnotation(Scheduled.class);

        assertThat(scheduled)
                .as("@Scheduled MUST be present — without it the GDPR purge never runs")
                .isNotNull();
        assertThat(scheduled.cron())
                .as("daily 03:30 server-time cron locked in for predictable backup-window alignment")
                .isEqualTo("0 30 3 * * *");
    }

    @Test
    @DisplayName("runScheduled() carries @SchedulerLock with bounded lockAtMostFor/lockAtLeastFor")
    void runScheduledHasShedLock() throws NoSuchMethodException {
        Method method = SoftDeletePurgeJob.class.getMethod("runScheduled");
        SchedulerLock lock = method.getAnnotation(SchedulerLock.class);

        assertThat(lock)
                .as("@SchedulerLock MUST be present so multi-replica deploys do not race the purge tx")
                .isNotNull();
        assertThat(lock.name()).isEqualTo("SoftDeletePurgeJob_runScheduled");
        assertThat(lock.lockAtMostFor()).isEqualTo("PT25M");
        assertThat(lock.lockAtLeastFor()).isEqualTo("PT1M");
    }

    @Test
    @DisplayName("enabled field is bound to ${app.purge.softDelete.enabled:false}")
    void enabledFieldBindingIsStable() throws NoSuchFieldException {
        Field enabled = SoftDeletePurgeJob.class.getDeclaredField("enabled");
        Value value = enabled.getAnnotation(Value.class);

        assertThat(value)
                .as("enabled field MUST be @Value-annotated, otherwise the YAML flag never reaches the JVM")
                .isNotNull();
        // The placeholder default stays `false` here on the FIELD — application-prod.yml
        // is what flips it on for the prod profile (T2-E). Renaming the property key
        // here would silently revert the prod default to false.
        assertThat(value.value()).isEqualTo("${app.purge.softDelete.enabled:false}");
    }
}
