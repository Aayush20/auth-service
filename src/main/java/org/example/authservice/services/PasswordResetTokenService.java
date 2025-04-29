package org.example.authservice.services;

import lombok.RequiredArgsConstructor;
import org.example.authservice.exceptions.TokenExpiredException;
import org.example.authservice.exceptions.TokenNotFoundException;
import org.example.authservice.models.PasswordResetToken;
import org.example.authservice.models.User;
import org.example.authservice.repositories.PasswordResetTokenRepository;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class PasswordResetTokenService {

    private final PasswordResetTokenRepository passwordResetTokenRepository;

    public PasswordResetToken createToken(User user, long durationHours) {
        passwordResetTokenRepository.deleteByUser(user); // Ensure only one active token

        String token = UUID.randomUUID().toString();
        PasswordResetToken resetToken = new PasswordResetToken(user, token, durationHours);
        return passwordResetTokenRepository.save(resetToken);
    }

    public User validateToken(String token) {
        PasswordResetToken resetToken = passwordResetTokenRepository.findByToken(token)
                .orElseThrow(() -> new TokenNotFoundException("Invalid password reset token."));

        if (resetToken.getExpiryDate().isBefore(Instant.now())) {
            throw new TokenExpiredException("Password reset token has expired.");
        }

        return resetToken.getUser();
    }

    public void deleteToken(String token) {
        passwordResetTokenRepository.findByToken(token).ifPresent(passwordResetTokenRepository::delete);
    }
}
