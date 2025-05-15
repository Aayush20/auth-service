package org.example.authservice.services;

import org.example.authservice.configs.RbacProperties;
import org.example.authservice.dtos.UserRegistrationDTO;
import org.example.authservice.models.Role;
import org.example.authservice.models.User;
import org.example.authservice.repositories.RoleRepository;
import org.example.authservice.repositories.TokenRepository;
import org.example.authservice.repositories.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;

class UserServiceTest {

    private UserService userService;
    private UserRepository userRepository;
    private RoleRepository roleRepository;
    private TokenRepository tokenRepository;
    private BCryptPasswordEncoder passwordEncoder;
    private RbacProperties rbacProperties;
    private SendGridEmailService sendGridEmailService;

    @BeforeEach
    void setUp() {
        userRepository = Mockito.mock(UserRepository.class);
        roleRepository = Mockito.mock(RoleRepository.class);
        tokenRepository = Mockito.mock(TokenRepository.class);
        passwordEncoder = new BCryptPasswordEncoder(); // real encoder
        rbacProperties = Mockito.mock(RbacProperties.class);
        sendGridEmailService = Mockito.mock(SendGridEmailService.class);

        userService = new UserService(tokenRepository, rbacProperties, userRepository, roleRepository, passwordEncoder, sendGridEmailService);
    }

    @Test
    void registerUser_success() {
        // Given
        UserRegistrationDTO dto = new UserRegistrationDTO();
        dto.setName("Test User");
        dto.setEmail("test@example.com");
        dto.setPassword("Test@1234");
        dto.setPhoneNumber("1234567890");

        when(userRepository.findByEmail(anyString())).thenReturn(Optional.empty());

        Role role = new Role();
        role.setValue(Role.RoleName.valueOf("CUSTOMER"));

        when(roleRepository.findByValue(anyString())).thenReturn(Optional.of(role));
        when(rbacProperties.getDefaultRole()).thenReturn("CUSTOMER");

        // When
        String result = userService.registerUser(dto);

        // Then
        assertNotNull(result);
        assertTrue(result.contains("User registered successfully"));
    }

    @Test
    void registerUser_emailAlreadyExists() {
        // Given
        UserRegistrationDTO dto = new UserRegistrationDTO();
        dto.setEmail("existing@example.com");

        when(userRepository.findByEmail(anyString())).thenReturn(Optional.of(new User()));

        // When
        String result = userService.registerUser(dto);

        // Then
        assertEquals("Error: Email already exists.", result);
    }
}
