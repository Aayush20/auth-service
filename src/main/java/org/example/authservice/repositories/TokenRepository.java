package org.example.authservice.repositories;

import org.example.authservice.models.Token;
import org.example.authservice.models.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token, Long> {

    Optional<Token> findByToken(String token);

    void deleteByUser(User user);
}
