package com.fivucsas.identity.repository;

import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserRepository extends JpaRepository<User, UUID> {

    Optional<User> findByEmail(String email);

    boolean existsByEmail(String email);

    List<User> findByStatus(UserStatus status);

    long countByStatus(UserStatus status);

    long countByIsBiometricEnrolled(boolean enrolled);

    @Query("SELECT COALESCE(SUM(u.verificationCount), 0) FROM User u")
    Long sumVerificationCount();

    @Query("SELECT u FROM User u WHERE " +
            "LOWER(CONCAT(u.firstName, ' ', u.lastName)) LIKE LOWER(CONCAT('%', :query, '%')) OR " +
            "LOWER(u.email) LIKE LOWER(CONCAT('%', :query, '%')) OR " +
            "u.idNumber LIKE CONCAT('%', :query, '%')")
    List<User> searchUsers(@Param("query") String query);
}
