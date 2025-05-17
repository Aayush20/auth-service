package org.example.authservice.configs;

import jakarta.annotation.PostConstruct;
import org.example.authservice.models.Role;
import org.example.authservice.models.User;
import org.example.authservice.repositories.RoleRepository;
import org.example.authservice.repositories.UserRepository;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

@Component
public class DataSeeder {

    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    public DataSeeder(RoleRepository roleRepository, UserRepository userRepository, BCryptPasswordEncoder passwordEncoder) {
        this.roleRepository = roleRepository;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @PostConstruct
    public void seed() {
        seedRoles();
        seedAdminUser();
        seedInternalClients();
    }

    private void seedRoles() {
        Arrays.asList(Role.RoleName.USER, Role.RoleName.ADMIN, Role.RoleName.SERVICE).forEach(roleName -> {
            if (roleRepository.findByValue(roleName).isEmpty()) {
                Role role = new Role();
                role.setValue(roleName);
                roleRepository.save(role);
                System.out.println("[SEED] Created role: " + roleName);
            }
        });
    }

    private void seedAdminUser() {
        Optional<User> adminOpt = userRepository.findByEmail("admin@example.com");
        if (adminOpt.isEmpty()) {
            User admin = new User();
            admin.setName("Admin");
            admin.setEmail("admin@example.com");
            admin.setEmailVerified(true);
            admin.setPhoneNumber("9999999999");
            admin.setHashedPassword(passwordEncoder.encode("admin@123"));

            Role adminRole = roleRepository.findByValue(Role.RoleName.ADMIN).orElseThrow();
            Role userRole = roleRepository.findByValue(Role.RoleName.USER).orElseThrow();
            admin.setRoles(Arrays.asList(adminRole, userRole));

            userRepository.save(admin);
            System.out.println("[SEED] Created default admin user.");
        }
    }

    private void seedInternalClients() {
        seedClient("gateway@example.com", "gateway@123", Role.RoleName.SERVICE);
        seedClient("order@example.com", "order@123", Role.RoleName.SERVICE);
        seedClient("prod-cat@example.com", "prodcat@123", Role.RoleName.SERVICE);
        seedClient("payment@example.com", "payment@123", Role.RoleName.SERVICE);
    }

    private void seedClient(String email, String password, Role.RoleName roleName) {
        if (userRepository.findByEmail(email).isEmpty()) {
            User user = new User();
            user.setName(email.split("@")[0]);
            user.setEmail(email);
            user.setEmailVerified(true);
            user.setPhoneNumber("0000000000");
            user.setHashedPassword(passwordEncoder.encode(password));

            Role role = roleRepository.findByValue(roleName).orElseThrow();
            user.setRoles(List.of(role));

            userRepository.save(user);
            System.out.println("[SEED] Created internal service user: " + email);
        }
    }
}
