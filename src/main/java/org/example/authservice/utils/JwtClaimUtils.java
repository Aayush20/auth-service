
package org.example.authservice.utils;

import org.springframework.security.oauth2.jwt.Jwt;

import java.util.List;

public class JwtClaimUtils {

    public static String getSubject(Jwt jwt) {
        return jwt.getSubject();
    }

    public static boolean hasScope(Jwt jwt, String scope) {
        return jwt.getClaimAsStringList("scope").contains(scope);
    }

    public static boolean hasRole(Jwt jwt, String role) {
        return jwt.getClaimAsStringList("roles").contains(role);
    }

    public static boolean isInternalService(Jwt jwt, List<String> allowedSubjects) {
        return allowedSubjects.contains(jwt.getSubject());
    }
}
