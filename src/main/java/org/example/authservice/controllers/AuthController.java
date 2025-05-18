package org.example.authservice.controllers;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.MeterRegistry;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.example.authservice.configs.AuthValidationProperties;
import org.example.authservice.dtos.*;
import org.example.authservice.models.RefreshToken;
import org.example.authservice.models.Token;
import org.example.authservice.models.User;
import org.example.authservice.models.Role;
import org.example.authservice.ratelimit.RateLimit;
import org.example.authservice.repositories.RefreshTokenRepository;
import org.example.authservice.repositories.TokenRepository;
import org.example.authservice.repositories.UserRepository;
import org.example.authservice.security.jwt.JwtService;
import org.example.authservice.security.models.CustomUserDetails;
import org.example.authservice.services.*;
import org.example.authservice.utils.JwtClaimUtils;
import org.example.authservice.utils.TokenGenerator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.time.Duration;
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
    @Autowired private UserRepository userRepository;
    @Autowired private TokenRepository tokenRepository;
    @Autowired private RefreshTokenRepository refreshTokenRepository;
    @Autowired private BCryptPasswordEncoder passwordEncoder;
    @Autowired private JwtService jwtService;
    @Autowired private RefreshTokenService refreshTokenService;
    @Autowired private SendGridEmailService emailService;
    @Autowired private RefreshTokenBlacklistService blacklistService;
    @Autowired private AuthValidationProperties validationProps;
    @Autowired private StringRedisTemplate redisTemplate;
    @Autowired private MeterRegistry meterRegistry;




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
        List<String> roles = user.getRoles().stream().map(Role::getValue).map(Enum::name).collect(Collectors.toList());
        eventPublisher.publishEvent(new UserRegisteredEvent(this, user.getId(), user.getEmail(), roles));

        return ResponseEntity.status(HttpStatus.CREATED).body(result);
    }

    @RateLimit(requests = 5, durationSeconds = 60)
    @Operation(summary = "User login and get access + refresh token")
    @ApiResponse(responseCode = "200", description = "JWT access and refresh tokens issued")
    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequestDTO loginDto) {

        UsernamePasswordAuthenticationToken authRequest =
                new UsernamePasswordAuthenticationToken(loginDto.getEmail(), loginDto.getPassword());

        try {
            Authentication authentication = authenticationManager.authenticate(authRequest);
            CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
            User user = userService.getByEmailOrThrow(userDetails.getUsername());
            if (!user.isEmailVerified()) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Email not verified. Please verify your email first.");
            }

            String accessToken = jwtService.generateAccessToken(user);
            String refreshToken = jwtService.generateRefreshToken(user);
            refreshTokenService.create(user, refreshToken);

            return ResponseEntity.ok(new AuthResponseDTO(accessToken, refreshToken));
        } catch (AuthenticationException ex) {

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
        }
    }

    @Operation(summary = "Refresh access token using a valid refresh token")
    //@PreAuthorize("isAuthenticated()")
    @RateLimit(requests = 10, durationSeconds = 60)
    @PreAuthorize("hasAuthority('SCOPE_auth.refresh')")
    @ApiResponse(responseCode = "200", description = "New access token issued")
    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@RequestBody RefreshRequestDTO request) {
        String oldTokenStr = request.getRefreshToken();

        // 🔐 Block if token is blacklisted
        if (blacklistService.isBlacklisted(oldTokenStr)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token has been revoked or reused");
        }

        Optional<RefreshToken> oldToken = refreshTokenService.findByToken(oldTokenStr);
        if (oldToken.isEmpty() || refreshTokenService.isExpired(oldToken.get())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Expired or invalid");
        }

        User user = oldToken.get().getUser();
        refreshTokenService.revokeToken(oldToken.get());

        // 🔒 Blacklist it for same TTL
        Duration remainingTtl = Duration.between(Instant.now(), oldToken.get().getExpiryDate());
        blacklistService.blacklist(oldTokenStr, remainingTtl);

        String newRefresh = jwtService.generateRefreshToken(user);
        refreshTokenService.create(user, newRefresh);
        String newAccess = jwtService.generateAccessToken(user);

        return ResponseEntity.ok(new AuthResponseDTO(newAccess, newRefresh));
    }


    @Operation(summary = "Validate JWT token for internal services")
    @PreAuthorize("hasAuthority('SCOPE_internal.call')")
    @PostMapping("/validate")
    public ResponseEntity<TokenIntrospectionResponseDTO> validateToken(
            @AuthenticationPrincipal Jwt jwt,
            @RequestHeader("Authorization") String tokenHeader
    ) {
        if (!JwtClaimUtils.isInternalService(jwt, validationProps.getInternalAllowedSubjects())) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }

        String token = tokenHeader.replace("Bearer ", "").trim();
        String cacheKey = "introspect:" + token;

        try {
            // 1. Check cache
            String cached = redisTemplate.opsForValue().get(cacheKey);
            if (cached != null) {
                meterRegistry.counter("auth.introspection.cache.hit").increment();
                TokenIntrospectionResponseDTO response = new ObjectMapper().readValue(cached, TokenIntrospectionResponseDTO.class);
                return ResponseEntity.ok(response);
            }

            // 2. Decode + build response
            Jwt decoded = authService.decodeAndValidate(token);
            TokenIntrospectionResponseDTO response = new TokenIntrospectionResponseDTO();
            response.setActive(true);
            response.setSub(decoded.getSubject());
            response.setEmail(decoded.getClaimAsString("email"));
            response.setExp(decoded.getExpiresAt().toEpochMilli());
            response.setScopes(decoded.getClaimAsStringList("scope"));
            response.setRoles(decoded.getClaimAsStringList("roles"));

            meterRegistry.counter("auth.introspection.cache.miss").increment();
            // 3. Store in cache (TTL = 5 min)
            redisTemplate.opsForValue().set(cacheKey, new ObjectMapper().writeValueAsString(response), Duration.ofMinutes(5));

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.internalServerError().build();
        }
    }




    @RateLimit(requests = 5, durationSeconds = 60)

    @PostMapping("/verify-email")
    @Operation(summary = "Verify email using token")
    public ResponseEntity<String> verifyEmail(@RequestParam("token") String tokenValue) {
        Optional<Token> optionalToken = tokenRepository.findByToken(tokenValue);
        if (optionalToken.isEmpty()) return ResponseEntity.badRequest().body("Invalid token.");

        Token token = optionalToken.get();
        if (token.getExpiryDate().isBefore(Instant.now()))
            return ResponseEntity.badRequest().body("Token has expired.");

        User user = token.getUser();
        if (!user.isEmailVerified()) {
            user.setEmailVerified(true);
            userRepository.save(user);
        }

        tokenRepository.delete(token);
        return ResponseEntity.ok("Email verified successfully.");
    }

    @RateLimit(requests = 3, durationSeconds = 60)
    @PostMapping("/resend-verification")
    @Operation(summary = "Resend email verification token")
    public ResponseEntity<String> resendVerification(@RequestParam String email) {
        Optional<User> optionalUser = userRepository.findByEmail(email);
        if (optionalUser.isEmpty()) return ResponseEntity.badRequest().body("User not found.");
        User user = optionalUser.get();

        if (user.isEmailVerified()) return ResponseEntity.ok("Email already verified.");

        // Optional: delete previous verification tokens
        tokenRepository.deleteByUserIdAndType(user.getId(), Token.TokenType.EMAIL_VERIFICATION);

        String tokenValue = TokenGenerator.generateToken();
        Token token = new Token();
        token.setToken(tokenValue);
        token.setUser(user);
        token.setExpiryDate(Instant.now().plus(30, ChronoUnit.MINUTES));
        token.setType(Token.TokenType.EMAIL_VERIFICATION);
        tokenRepository.save(token);

        try {
            Map<String, Object> model = new HashMap<>();
            model.put("userName", user.getName());
            model.put("token", tokenValue);
            emailService.sendTemplatedEmail(user.getEmail(), "Email Verification Token", "verify-email", model);
            return ResponseEntity.ok("Verification email resent.");
        } catch (IOException e) {
            return ResponseEntity.internalServerError().body("Failed to send email.");
        }
    }

    @RateLimit(requests = 3, durationSeconds = 60)
    @Operation(summary = "Request password reset email")
    @PostMapping("/forgot-password")
    public ResponseEntity<String> forgotPassword(@RequestParam("email") String email) {
        Optional<User> optionalUser = userRepository.findByEmail(email);
        if (optionalUser.isEmpty()) {
            return ResponseEntity.badRequest().body("User not found.");
        }

        User user = optionalUser.get();
        String tokenValue = TokenGenerator.generateToken();

        Token token = new Token();
        token.setToken(tokenValue);
        token.setType(Token.TokenType.PASSWORD_RESET);
        token.setExpiryDate(Instant.now().plus(1, ChronoUnit.HOURS));
        token.setUser(user);
        tokenRepository.save(token);

        try {
            Map<String, Object> model = new HashMap<>();
            model.put("userName", user.getName());
            model.put("token", tokenValue);
            emailService.sendTemplatedEmail(user.getEmail(), "Reset Your Password", "reset-password", model);

        } catch (IOException e) {
            // Optional: Log or alert in production
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Failed to send password reset email.");
        }

        return ResponseEntity.ok("Password reset email sent successfully!");
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

    @Operation(summary = "Logout and revoke refresh token")
    //@PreAuthorize("isAuthenticated()")
    @PreAuthorize("hasAuthority('SCOPE_auth.logout')")
    @DeleteMapping("/logout")
    public ResponseEntity<String> logout(@RequestBody RefreshRequestDTO request) {
        String tokenValue = request.getRefreshToken();
        Optional<RefreshToken> token = refreshTokenService.findByToken(tokenValue);

        if (token.isPresent()) {
            RefreshToken refreshToken = token.get();
            refreshTokenService.revokeToken(refreshToken);

            Duration ttl = Duration.between(Instant.now(), refreshToken.getExpiryDate());
            blacklistService.blacklist(tokenValue, ttl);

            return ResponseEntity.ok("Refresh token revoked and blacklisted.");
        } else {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Token not found");
        }
    }

    @Scheduled(cron = "0 0 2 * * ?") // every night at 2 AM
    public void purgeExpiredTokens() {
        List<RefreshToken> all = refreshTokenRepository.findAll();
        all.stream()
                .filter(refreshTokenService::isExpired)
                .forEach(refreshTokenRepository::delete);
    }

    @Scheduled(cron = "0 0 3 * * ?") // Every day at 3 AM
    public void purgeExpiredEmailResetTokens() {
        tokenRepository.deleteAllByExpiryDateBefore(Instant.now());
    }

}
