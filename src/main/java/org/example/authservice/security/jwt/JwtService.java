package org.example.authservice.security.jwt;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.example.authservice.models.User;
import org.springframework.context.annotation.Configuration;

import java.security.Key;
import java.time.Instant;
import java.util.Date;
import java.util.Map;

@Configuration
public class JwtService {

    private static final String SECRET_KEY = "aayush-production-grade-key-should-be-at-least-256-bits-long";
    private static final long ACCESS_TOKEN_EXPIRY_SECONDS = 15 * 60; // 15 mins
    private static final long REFRESH_TOKEN_EXPIRY_SECONDS = 7 * 24 * 60 * 60; // 7 days

    public String generateAccessToken(User user) {
        Map<String, Object> claims = JwtClaimsBuilder.buildClaims(user);
        return buildToken(claims, user.getEmail(), ACCESS_TOKEN_EXPIRY_SECONDS);
    }

    public String generateRefreshToken(User user) {
        Map<String, Object> claims = JwtClaimsBuilder.buildRefreshClaims(user);
        return buildToken(claims, user.getEmail(), REFRESH_TOKEN_EXPIRY_SECONDS);
    }

    private String buildToken(Map<String, Object> claims, String subject, long expirySeconds) {
        Instant now = Instant.now();
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(now.plusSeconds(expirySeconds)))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
