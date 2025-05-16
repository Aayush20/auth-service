package org.example.authservice.controllers;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.example.authservice.models.Role;
import org.example.authservice.models.User;
import org.example.authservice.repositories.RoleRepository;
import org.example.authservice.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@RestController
@RequestMapping("/api/admin")
@Tag(name = "Admin APIs")
public class AdminController {

    @Autowired private UserRepository userRepository;
    @Autowired private RoleRepository roleRepository;

    @Operation(summary = "Update a user's role (admin only)")
    @PreAuthorize("hasAuthority('SCOPE_admin.write')")
    @PutMapping("/users/{userId}/role")
    public ResponseEntity<String> updateUserRole(@PathVariable Long userId, @RequestParam String roleValue) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        Role.RoleName roleEnum;
        try {
            roleEnum = Role.RoleName.valueOf(roleValue.toUpperCase());
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body("Invalid role: " + roleValue);
        }

        Optional<Role> newRole = roleRepository.findByValue(roleEnum);
        if (newRole.isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body("Role " + roleValue + " does not exist.");
        }

        user.getRoles().clear();
        user.getRoles().add(newRole.get());
        userRepository.save(user);
        return ResponseEntity.ok("User role updated successfully.");
    }
}

