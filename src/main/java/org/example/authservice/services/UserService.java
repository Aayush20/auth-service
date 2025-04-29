package org.example.authservice.services;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

import org.example.authservice.configs.RbacProperties;
import org.example.authservice.dtos.UserRegistrationDTO;
import org.example.authservice.models.Role;
import org.example.authservice.models.Token;
import org.example.authservice.models.User;
import org.example.authservice.repositories.RoleRepository;
import org.example.authservice.repositories.TokenRepository;
import org.example.authservice.repositories.UserRepository;
import org.example.authservice.utils.PasswordValidator;
import org.example.authservice.utils.TokenGenerator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    private final TokenRepository tokenRepository;
    private final RbacProperties rbacProperties;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    @Autowired
    public UserService(TokenRepository tokenRepository,
                       RbacProperties rbacProperties,
                       UserRepository userRepository,
                       RoleRepository roleRepository,
                       BCryptPasswordEncoder passwordEncoder) {
        this.tokenRepository = tokenRepository;
        this.rbacProperties = rbacProperties;
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
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

        Optional<Role> defaultRole = roleRepository.findByValue(rbacProperties.getDefaultRole());
        if (defaultRole.isEmpty()) {
            throw new IllegalStateException("Default role '" + rbacProperties.getDefaultRole() + "' not found.");
        }
        user.getRoles().add(defaultRole.get());

        userRepository.save(user);

        // Create Email Verification Token
        String tokenValue = TokenGenerator.generateToken();
        Token token = new Token();
        token.setToken(tokenValue);
        token.setType(Token.TokenType.EMAIL_VERIFICATION);
        token.setExpiryDate(Instant.now().plus(24, ChronoUnit.HOURS));
        token.setUser(user);
        tokenRepository.save(token);

        // For now, return the token manually (simulate sending email)
        return "User registered successfully! Please verify your email using token: " + tokenValue;
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
