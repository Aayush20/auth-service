package org.example.authservice.services;

import org.example.authservice.models.RefreshToken;
import org.example.authservice.models.User;
import org.example.authservice.repositories.RefreshTokenRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Optional;

@Service
public class RefreshTokenService {

    private static final long REFRESH_TOKEN_VALIDITY_MINUTES = 10080; // 7 days

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    public RefreshToken create(User user, String rawToken) {
        RefreshToken token = new RefreshToken(user, rawToken, REFRESH_TOKEN_VALIDITY_MINUTES);
        return refreshTokenRepository.save(token);
    }

    public Optional<RefreshToken> findByToken(String tokenStr) {
        return refreshTokenRepository.findByToken(tokenStr);
    }

    public boolean isExpired(RefreshToken token) {
        return token.getExpiryDate().isBefore(Instant.now()) || token.isRevoked();
    }

    public void revokeToken(RefreshToken token) {
        token.setRevoked(true);
        token.setRevokedAt(Instant.now());
        refreshTokenRepository.save(token);
    }

    public void revokeAllTokensForUser(User user) {
        refreshTokenRepository.findAllByUserId(user.getId())
                .forEach(token -> {
                    token.setRevoked(true);
                    token.setRevokedAt(Instant.now());
                });
    }
}
