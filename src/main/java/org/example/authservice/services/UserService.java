package org.example.authservice.services;

import java.util.Optional;
import org.example.authservice.dtos.UserRegistrationDTO;
import org.example.authservice.models.User;
import org.example.authservice.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    public String registerUser(UserRegistrationDTO dto) {
        if (userRepository.findByEmail(dto.getEmail()).isPresent()) {
            return "Error: Email already exists.";
        }
        User user = new User();
        user.setName(dto.getName());
        user.setEmail(dto.getEmail());
        user.setPhoneNumber(dto.getPhoneNumber());
        // Encrypt the password before saving
        user.setHashedPassword(passwordEncoder.encode(dto.getPassword()));
        user.setEmailVerified(false);
        // Optionally, assign a default role here
        userRepository.save(user);
        return "User registered successfully!";
    }

    public Optional<User> getUserById(Long userId) {
        return userRepository.findById(userId);
    }
}
