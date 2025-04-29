package org.example.authservice.controllers;

import lombok.RequiredArgsConstructor;
import org.example.authservice.models.User;
import org.example.authservice.services.UserService;
import org.example.authservice.services.VerificationTokenService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class EmailVerificationController {

    private final VerificationTokenService verificationTokenService;
    private final UserService userService;

    @PostMapping("/verify-email")
    public ResponseEntity<String> verifyEmail(@RequestParam("token") String token) {
        User user = verificationTokenService.validateToken(token);

        if (user.isEmailVerified()) {
            return ResponseEntity.ok("Email already verified.");
        }

        user.setEmailVerified(true);
        userService.save(user);

        verificationTokenService.deleteToken(token);

        return ResponseEntity.ok("Email verified successfully.");
    }
}
