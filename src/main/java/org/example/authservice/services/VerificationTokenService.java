package org.example.authservice.services;

import lombok.RequiredArgsConstructor;
import org.example.authservice.exceptions.TokenExpiredException;
import org.example.authservice.exceptions.TokenNotFoundException;
import org.example.authservice.models.User;
import org.example.authservice.models.VerificationToken;
import org.example.authservice.repositories.VerificationTokenRepository;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class VerificationTokenService {

    private final VerificationTokenRepository verificationTokenRepository;

    public VerificationToken createToken(User user, long hoursUntilExpiry) {
        // Remove existing tokens for idempotency
        verificationTokenRepository.deleteByUser(user);

        String token = UUID.randomUUID().toString();
        VerificationToken verificationToken = new VerificationToken(user, token, hoursUntilExpiry);
        return verificationTokenRepository.save(verificationToken);
    }

    public User validateToken(String token) {
        VerificationToken verificationToken = verificationTokenRepository.findByToken(token)
                .orElseThrow(() -> new TokenNotFoundException("Invalid verification token."));

        if (verificationToken.getExpiryDate().isBefore(Instant.now())) {
            throw new TokenExpiredException("Verification token has expired.");
        }

        return verificationToken.getUser();
    }

    public void deleteToken(String token) {
        verificationTokenRepository.findByToken(token).ifPresent(verificationTokenRepository::delete);
    }
}
