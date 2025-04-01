package org.example.authservice.services;

import java.util.Optional;

import org.example.authservice.configs.RbacProperties;
import org.example.authservice.dtos.UserRegistrationDTO;
import org.example.authservice.models.Role;
import org.example.authservice.models.User;
import org.example.authservice.repositories.RoleRepository;
import org.example.authservice.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    // Injecting the default role via configuration:
    private final RbacProperties rbacProperties;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    @Autowired
    public UserService(RbacProperties rbacProperties,
                       UserRepository userRepository,
                       RoleRepository roleRepository,
                       BCryptPasswordEncoder passwordEncoder) {
        this.rbacProperties = rbacProperties;
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public String registerUser(UserRegistrationDTO dto) {
        if (userRepository.findByEmail(dto.getEmail()).isPresent()) {
            return "Error: Email already exists.";
        }
//        if (userRepository.findByPhoneNumber(dto.getPhoneNumber()).isPresent()) {
//            return "Error: Phone number already exists.";
//        }
        User user = new User();
        user.setName(dto.getName());
        user.setEmail(dto.getEmail());
        user.setPhoneNumber(dto.getPhoneNumber());
        user.setHashedPassword(passwordEncoder.encode(dto.getPassword()));
        user.setEmailVerified(false);

        // Always assign the default role in the system (e.g., CUSTOMER),
        // never let the client decide this.
        Optional<Role> defaultRole = roleRepository.findByValue(rbacProperties.getDefaultRole());
        if (defaultRole.isEmpty()) {
            // Depending on policy, you can either create it at startup or throw an error.
            throw new IllegalStateException("Default role '" + rbacProperties.getDefaultRole() + "' not found.");
        }
        user.getRoles().add(defaultRole.get());

        userRepository.save(user);
        return "User registered successfully!";
    }

    public Optional<User> getUserById(Long userId) {
        return userRepository.findById(userId);
    }

    public User findByEmail(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("User not found with email: " + email));
    }
}
