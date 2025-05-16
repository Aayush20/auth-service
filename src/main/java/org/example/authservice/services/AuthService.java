package org.example.authservice.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Service;

import java.time.Instant;

@Service
public class AuthService {

    @Autowired
    private JwtDecoder jwtDecoder;

    /**
     * Validates the JWT token by:
     *   - Stripping the "Bearer " prefix if present
     *   - Decoding the token (which verifies signature)
     *   - Checking the expiration time
     *   - Ensuring required claims exist (e.g. subject)
     *   - Optionally comparing issuer and audience claims to expected values
     *
     * @param token the Authorization header value containing the token.
     * @return true if the token is valid; false otherwise.
     */
    public boolean validateToken(String token) {
        try {
            // Remove "Bearer " if it exists
            if (token.startsWith("Bearer ")) {
                token = token.substring(7);
            }

            // Decode the token. This step verifies the signature automatically.
            Jwt jwt = jwtDecoder.decode(token);

            // Check expiration: jwtDecoder may already do this, but we verify explicitly.
            if (jwt.getExpiresAt() == null || Instant.now().isAfter(jwt.getExpiresAt())) {
                // Token has expired.
                return false;
            }

            // Check that a subject claim is present.
            if (jwt.getSubject() == null || jwt.getSubject().isEmpty()) {
                return false;
            }

            // Optional: Verify the issuer claim matches your expected issuer.
//            String expectedIssuer = "https://your-authorization-server.com"; // Update to your expected issuer URL.
//            if (jwt.getIssuer() == null || !expectedIssuer.equals(jwt.getIssuer().toString())) {
//                return false;
//            }

            // Optional: Check audience claim if you have one.
            // For example, if your token must be issued for a specific audience, you can check it:
            // List<String> audiences = jwt.getAudience();
            // if (audiences == null || !audiences.contains("your-api-audience")) {
            //     return false;
            // }

            // If all checks pass, the token is valid.
            return true;
        } catch (JwtException ex) {
            // If any error occurs during decoding/validation, the token is considered invalid.
            return false;
        }
    }

    public Jwt decodeAndValidate(String token) {
        JwtDecoder decoder = JwtDecoders.fromIssuerLocation("http://localhost:8080"); // Or use Nimbus
        return decoder.decode(token);
    }

}
