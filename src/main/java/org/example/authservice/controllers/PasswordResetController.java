package org.example.authservice.controllers;

import lombok.RequiredArgsConstructor;
import org.example.authservice.models.User;
import org.example.authservice.services.PasswordResetTokenService;
import org.example.authservice.services.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class PasswordResetController {

    private final PasswordResetTokenService passwordResetTokenService;
    private final UserService userService;

    @PostMapping("/forgot-password")
    public ResponseEntity<String> forgotPassword(@RequestParam("email") String email) {
        User user = userService.getByEmailOrThrow(email);
        var token = passwordResetTokenService.createToken(user, 1); // 1 hour expiry

        String resetLink = "http://localhost:8080/api/auth/reset-password?token=" + token.getToken();
        System.out.println("Mock reset email sent: " + resetLink); // Replace with real mail logic later

        return ResponseEntity.ok("Password reset link has been sent.");
    }

    @PostMapping("/reset-password")
    public ResponseEntity<String> resetPassword(@RequestParam("token") String token,
                                                @RequestParam("newPassword") String newPassword) {
        User user = passwordResetTokenService.validateToken(token);

        userService.updatePassword(user, newPassword);
        passwordResetTokenService.deleteToken(token);

        return ResponseEntity.ok("Password has been reset successfully.");
    }
}
