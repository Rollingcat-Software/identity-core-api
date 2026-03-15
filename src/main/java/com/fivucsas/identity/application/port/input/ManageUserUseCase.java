package com.fivucsas.identity.application.port.input;

import com.fivucsas.identity.application.dto.command.CreateUserCommand;
import com.fivucsas.identity.application.dto.command.UpdateUserCommand;
import com.fivucsas.identity.application.dto.query.GetAllUsersQuery;
import com.fivucsas.identity.application.dto.query.GetUserByIdQuery;
import com.fivucsas.identity.application.dto.query.SearchUsersQuery;
import com.fivucsas.identity.application.dto.response.UserResponse;

import java.util.List;

/**
 * Input port for user management operations (CRUD).
 *
 * This interface defines the contract for managing users:
 * create, read, update, delete operations.
 *
 * Following principles:
 * - Interface Segregation: Focused on user management
 * - Dependency Inversion: Application defines the port
 * - CQRS: Separates commands (create, update, delete) from queries (get, search)
 */
public interface ManageUserUseCase {

    /**
     * Creates a new user (admin operation).
     *
     * @param command the create user command
     * @return UserResponse with created user data
     * @throws com.fivucsas.identity.domain.exception.DuplicateEmailException if email already exists
     */
    UserResponse createUser(CreateUserCommand command);

    /**
     * Retrieves a user by ID.
     *
     * @param query the query containing user ID
     * @return UserResponse with user data
     * @throws com.fivucsas.identity.domain.exception.UserNotFoundException if user doesn't exist
     */
    UserResponse getUserById(GetUserByIdQuery query);

    /**
     * Retrieves all users.
     *
     * @param query the query for listing all users
     * @return List of UserResponse
     */
    List<UserResponse> getAllUsers(GetAllUsersQuery query);

    /**
     * Searches users by query string.
     *
     * @param query the search query
     * @return List of matching UserResponse
     */
    List<UserResponse> searchUsers(SearchUsersQuery query);

    /**
     * Updates an existing user.
     *
     * @param command the update user command
     * @return UserResponse with updated user data
     * @throws com.fivucsas.identity.domain.exception.UserNotFoundException if user doesn't exist
     */
    UserResponse updateUser(UpdateUserCommand command);

    /**
     * Deletes a user by ID.
     *
     * @param userId the user ID to delete
     * @throws com.fivucsas.identity.domain.exception.UserNotFoundException if user doesn't exist
     */
    void deleteUser(String userId);

    /**
     * Counts all users in the system.
     *
     * @return total number of users
     */
    long countAllUsers();
}
