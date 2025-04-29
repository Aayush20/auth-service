package org.example.authservice.controllers;

import jakarta.validation.Valid;
import org.example.authservice.dtos.LoginRequestDTO;
import org.example.authservice.dtos.UserRegisteredEvent;
import org.example.authservice.dtos.UserRegistrationDTO;
import org.example.authservice.models.User;
import org.example.authservice.models.Role;
import org.example.authservice.repositories.UserRepository;
import org.example.authservice.security.models.CustomUserDetails;
import org.example.authservice.services.UserService;
import org.example.authservice.services.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.core.*;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private UserService userService;

    @Autowired
    private AuthService authService;

    @Autowired
    private ApplicationEventPublisher eventPublisher;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtEncoder jwtEncoder;

    @Autowired
    private UserRepository userRepository;

    // Endpoint for user registration.
    @PostMapping("/signup")
    public ResponseEntity<?> signUp(@Valid @RequestBody UserRegistrationDTO dto) {
        String result = userService.registerUser(dto);
        if (result.startsWith("Error:")) {
            return ResponseEntity.badRequest().body(result);
        }
        // Publish an event so that other microservices may receive user data.
        Optional<User> useropt = userService.findByEmail(dto.getEmail());
        User user = useropt.orElseThrow(() -> new IllegalStateException("User not found"));
        List<String> roles = user.getRoles().stream()
                .map(Role::getValue)
                .collect(Collectors.toList());
        eventPublisher.publishEvent(new UserRegisteredEvent(this, user.getId(), user.getEmail(),
                user.getRoles().stream().map(Role::getValue).collect(Collectors.toList())));


        return ResponseEntity.status(HttpStatus.CREATED).body(result);
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody
                                   LoginRequestDTO loginDto) {
        // Create the authentication token
        UsernamePasswordAuthenticationToken authRequest =
                new UsernamePasswordAuthenticationToken(loginDto.getEmail(), loginDto.getPassword());
        try {
            // Authenticate the user
            Authentication authentication = authenticationManager.authenticate(authRequest);
            CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();

            // Build the JWT token (this is just an example; adapt based on your JWT setup)
            Instant now = Instant.now();
            long expiry = 36000L; // expiration time in seconds
            JwtClaimsSet claims = JwtClaimsSet.builder()
                    .issuer("auth-service")
                    .issuedAt(now)
                    .expiresAt(now.plusSeconds(expiry))
                    .subject(userDetails.getUsername())
                    .claim("roles", userDetails.getAuthorities().stream()
                            .map(GrantedAuthority::getAuthority)
                            .collect(Collectors.toList()))
                    .build();

            String token = jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();

            Map<String, String> tokenResponse = new HashMap<>();
            tokenResponse.put("accessToken", token);
            return ResponseEntity.ok(tokenResponse);
        } catch (AuthenticationException ex) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
        }
    }

    // Token validation endpoint.
    @PostMapping("/validate")
    public ResponseEntity<Boolean> validateToken(@RequestHeader("Authorization") String token) {
        boolean valid = authService.validateToken(token);
        return ResponseEntity.ok(valid);
    }

    @PostMapping("/verify-email")
    public ResponseEntity<?> verifyEmail(@RequestParam("token") String token) {
        if (token == null || token.isEmpty()) {
            return ResponseEntity.badRequest().body("Verification token is missing.");
        }

        User user = userRepository.findByEmailVerificationToken(token)
                .orElse(null);

        if (user == null) {
            return ResponseEntity.badRequest().body("Invalid or expired verification token.");
        }

        if (user.isEmailVerified()) {
            return ResponseEntity.badRequest().body("Email already verified.");
        }

        user.setEmailVerified(true);
        user.setEmailVerificationToken(null); // optional - clear token after verification
        userRepository.save(user);

        return ResponseEntity.ok("Email verified successfully!");
    }
}

