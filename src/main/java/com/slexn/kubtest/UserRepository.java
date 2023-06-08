package com.slexn.multiboard.repository;

import com.slexn.multiboard.entities.documents.User;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends MongoRepository<User, String> {
    Optional<User> findByUsername(String username);

    Optional<User> findByEmail(String email);

    Boolean existsByUsername(String username);

    Boolean existsByEmail(String email);

    List<User> findUsersByWorkspaceIdsContaining(String id);

    List<User> findUsersByIdIn(List<String> ids);

    List<User> findUsersByWorkspaceIdsContainingAndEmailIn(String id, List<String> emails);

    List<User> findUsersByEmailIn(List<String> emails);

    List<User> findUsersByOwnedBuildsContaining(String buildId);

    boolean existsById(String id);
}