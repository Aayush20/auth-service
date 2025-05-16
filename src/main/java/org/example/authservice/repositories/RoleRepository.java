package org.example.authservice.repositories;

import org.example.authservice.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByValue(Role.RoleName value);
}
