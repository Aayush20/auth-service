package org.example.authservice.security.jwt;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import org.example.authservice.models.User;

public class JwtClaimsBuilder {

    public static Map<String, Object> buildClaims(User user) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", user.getEmail());
        claims.put("userId", user.getId());
        claims.put("roles", user.getRoles().stream().map(r -> r.getValue().name()).collect(Collectors.toList()));
        claims.put("scopes", user.getScopes().stream().map(Enum::name).collect(Collectors.toList()));
        claims.put("email_verified", user.isEmailVerified());
        claims.put("type", "access");
        return claims;
    }

    public static Map<String, Object> buildRefreshClaims(User user) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", user.getEmail());
        claims.put("userId", user.getId());
        claims.put("type", "refresh");
        return claims;
    }
}
