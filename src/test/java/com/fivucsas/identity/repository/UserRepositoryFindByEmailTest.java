package com.fivucsas.identity.repository;

import com.fivucsas.identity.entity.User;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

/**
 * Unit test for the P1-6 fix on {@link UserRepository#findByEmail(String)}.
 *
 * <p>The method is now a {@code default} that delegates to the deterministically
 * ordered {@link UserRepository#findByEmailOrdered(String, Pageable)} and takes
 * the first row, so it can NEVER throw {@code NonUniqueResultException} when an
 * account-linked identity has the same email in more than one tenant (V66/V67/V70).
 * We mock only the ordered query (Mockito {@code CALLS_REAL_METHODS} runs the real
 * default body) and assert the delegation contract.</p>
 */
class UserRepositoryFindByEmailTest {

    private static final String EMAIL = "duplicate@example.com";

    private UserRepository repo() {
        // CALLS_REAL_METHODS executes the real default findByEmail body while
        // letting us stub the underlying findByEmailOrdered query method.
        return mock(UserRepository.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
    }

    @Test
    @DisplayName("returns empty when no live row matches the email")
    void returnsEmptyWhenNoMatch() {
        UserRepository repo = repo();
        when(repo.findByEmailOrdered(eq(EMAIL), eq(PageRequest.of(0, 1)))).thenReturn(List.of());

        assertThat(repo.findByEmail(EMAIL)).isEmpty();
    }

    @Test
    @DisplayName("returns the single match unchanged (normal login case)")
    void returnsSingleMatch() {
        UserRepository repo = repo();
        User only = mock(User.class);
        when(repo.findByEmailOrdered(eq(EMAIL), eq(PageRequest.of(0, 1)))).thenReturn(List.of(only));

        Optional<User> result = repo.findByEmail(EMAIL);

        assertThat(result).containsSame(only);
    }

    @Test
    @DisplayName("never throws on multiplicity — returns the first (oldest) row")
    void resolvesDeterministicallyOnDuplicates() {
        UserRepository repo = repo();
        User oldest = mock(User.class);
        // The query already ORDER BY createdAt ASC, id ASC + LIMIT 1, so the
        // backing call yields at most one row even when duplicates exist; the
        // default body must take that first row instead of failing.
        when(repo.findByEmailOrdered(eq(EMAIL), eq(PageRequest.of(0, 1)))).thenReturn(List.of(oldest));

        assertThatCode(() -> repo.findByEmail(EMAIL)).doesNotThrowAnyException();
        assertThat(repo.findByEmail(EMAIL)).containsSame(oldest);
    }
}
