package org.example.authservice.services;

import java.time.Instant;
import java.util.Optional;
import java.util.stream.Collectors;

import org.example.authservice.configs.RbacProperties;
import org.example.authservice.dtos.UserRegistrationDTO;
import org.example.authservice.models.Role;
import org.example.authservice.models.User;
import org.example.authservice.repositories.RoleRepository;
import org.example.authservice.repositories.UserRepository;
import org.example.authservice.utils.PasswordValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    private final RbacProperties rbacProperties;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    private final JwtEncoder jwtEncoder; //

    @Autowired
    public UserService(RbacProperties rbacProperties,
                       UserRepository userRepository,
                       RoleRepository roleRepository,
                       BCryptPasswordEncoder passwordEncoder,
                       JwtEncoder jwtEncoder) {
        this.rbacProperties = rbacProperties;
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtEncoder = jwtEncoder;
    }

    public String registerUser(UserRegistrationDTO dto) {
        if (userRepository.findByEmail(dto.getEmail()).isPresent()) {
            return "Error: Email already exists.";
        }

        User user = new User();
        user.setName(dto.getName());
        user.setEmail(dto.getEmail());
        user.setPhoneNumber(dto.getPhoneNumber());
        user.setHashedPassword(passwordEncoder.encode(dto.getPassword()));
        user.setEmailVerified(false);

        Optional<Role> defaultRole = roleRepository.findByValue(rbacProperties.getDefaultRole());
        if (defaultRole.isEmpty()) {
            throw new IllegalStateException("Default role '" + rbacProperties.getDefaultRole() + "' not found.");
        }
        user.getRoles().add(defaultRole.get());

        userRepository.save(user);

        // ✅ Generate JWT using Nimbus
        Instant now = Instant.now();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .subject(user.getEmail())
                .issuedAt(now)
                .expiresAt(now.plusSeconds(3600)) // 1 hour
                .claim("roles", user.getRoles().stream().map(Role::getValue).collect(Collectors.toList()))
                .build();

        String token = jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();

        return "User registered successfully! Token: " + token;
    }

    public Optional<User> getUserById(Long userId) {
        return userRepository.findById(userId);
    }

    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    public User getByEmailOrThrow(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("User not found with email: " + email));
    }

    public User save(User user) {
        return userRepository.save(user);
    }

    public void updatePassword(User user, String rawPassword) {
        String encoded = passwordEncoder.encode(rawPassword);
        user.setHashedPassword(encoded);
        userRepository.save(user);
    }

    public boolean isPasswordValid(String password) {
        return PasswordValidator.validate(password);
    }
}
