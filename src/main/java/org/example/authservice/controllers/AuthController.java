package org.example.authservice.controllers;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.parameters.RequestBody;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.example.authservice.dtos.LoginRequestDTO;
import org.example.authservice.dtos.UserRegisteredEvent;
import org.example.authservice.dtos.UserRegistrationDTO;
import org.example.authservice.models.Token;
import org.example.authservice.models.User;
import org.example.authservice.models.Role;
import org.example.authservice.repositories.TokenRepository;
import org.example.authservice.repositories.UserRepository;
import org.example.authservice.security.models.CustomUserDetails;
import org.example.authservice.services.UserService;
import org.example.authservice.services.AuthService;
import org.example.authservice.utils.TokenGenerator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.stream.Collectors;

@Tag(name = "Authentication API")
@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired private UserService userService;
    @Autowired private AuthService authService;
    @Autowired private ApplicationEventPublisher eventPublisher;
    @Autowired private AuthenticationManager authenticationManager;
    @Autowired private JwtEncoder jwtEncoder;
    @Autowired private UserRepository userRepository;
    @Autowired private TokenRepository tokenRepository;
    @Autowired private BCryptPasswordEncoder passwordEncoder;

    @Operation(summary = "User registration (signup)")
    @ApiResponse(responseCode = "201", description = "User created successfully")
    @PostMapping("/signup")
    public ResponseEntity<?> signUp(@Valid @RequestBody UserRegistrationDTO dto) {
        String result = userService.registerUser(dto);
        if (result.startsWith("Error:")) {
            return ResponseEntity.badRequest().body(result);
        }

        Optional<User> useropt = userService.findByEmail(dto.getEmail());
        User user = useropt.orElseThrow(() -> new IllegalStateException("User not found"));
        List<String> roles = user.getRoles().stream().map(Role::getValue).collect(Collectors.toList());
        eventPublisher.publishEvent(new UserRegisteredEvent(this, user.getId(), user.getEmail(), roles));

        return ResponseEntity.status(HttpStatus.CREATED).body(result);
    }

    @Operation(summary = "User login and JWT token issuance")
    @ApiResponse(responseCode = "200", description = "JWT issued")
    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequestDTO loginDto) {
        UsernamePasswordAuthenticationToken authRequest =
                new UsernamePasswordAuthenticationToken(loginDto.getEmail(), loginDto.getPassword());
        try {
            Authentication authentication = authenticationManager.authenticate(authRequest);
            CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();

            Instant now = Instant.now();
            JwtClaimsSet claims = JwtClaimsSet.builder()
                    .issuer("auth-service")
                    .issuedAt(now)
                    .expiresAt(now.plusSeconds(36000L))
                    .subject(userDetails.getUsername())
                    .claim("roles", userDetails.getAuthorities().stream()
                            .map(role -> role.getAuthority()).collect(Collectors.toList()))
                    .build();

            String token = jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
            return ResponseEntity.ok(Map.of("accessToken", token));
        } catch (AuthenticationException ex) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
        }
    }

    @Operation(summary = "Validate JWT token")
    @PostMapping("/validate")
    public ResponseEntity<Boolean> validateToken(@RequestHeader("Authorization") String token) {
        boolean valid = authService.validateToken(token);
        return ResponseEntity.ok(valid);
    }

    @Operation(summary = "Verify email using token")
    @PostMapping("/verify-email")
    public ResponseEntity<String> verifyEmail(@RequestParam("token") String tokenValue) {
        Optional<Token> optionalToken = tokenRepository.findByToken(tokenValue);
        if (optionalToken.isEmpty()) return ResponseEntity.badRequest().body("Invalid token.");

        Token token = optionalToken.get();
        if (token.getExpiryDate().isBefore(Instant.now()))
            return ResponseEntity.badRequest().body("Token has expired.");

        User user = token.getUser();
        user.setEmailVerified(true);
        userRepository.save(user);
        tokenRepository.delete(token);

        return ResponseEntity.ok("Email verified successfully.");
    }

    @Operation(summary = "Request password reset email")
    @PostMapping("/forgot-password")
    public ResponseEntity<String> forgotPassword(@RequestParam("email") String email) {
        Optional<User> optionalUser = userRepository.findByEmail(email);
        if (optionalUser.isEmpty()) return ResponseEntity.badRequest().body("User not found.");

        User user = optionalUser.get();
        String tokenValue = TokenGenerator.generateToken();

        Token token = new Token();
        token.setToken(tokenValue);
        token.setType(Token.TokenType.PASSWORD_RESET);
        token.setExpiryDate(Instant.now().plus(1, ChronoUnit.HOURS));
        token.setUser(user);
        tokenRepository.save(token);

        // sendEmail(user.getEmail(), tokenValue); // future
        return ResponseEntity.ok("Password reset token generated successfully!");
    }

    @Operation(summary = "Reset password using token")
    @PostMapping("/reset-password")
    public ResponseEntity<String> resetPassword(@RequestParam("token") String tokenValue,
                                                @RequestParam("newPassword") String newPassword) {
        Optional<Token> optionalToken = tokenRepository.findByToken(tokenValue);
        if (optionalToken.isEmpty()) return ResponseEntity.badRequest().body("Invalid token.");

        Token token = optionalToken.get();
        if (token.getExpiryDate().isBefore(Instant.now()))
            return ResponseEntity.badRequest().body("Token has expired.");

        User user = token.getUser();
        user.setHashedPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
        tokenRepository.delete(token);

        return ResponseEntity.ok("Password has been reset successfully.");
    }
}
