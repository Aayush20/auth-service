package org.example.authservice.security.models;


import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import org.example.authservice.models.Role;
import org.springframework.security.core.GrantedAuthority;

@JsonDeserialize
public class CustomGrantedAuthority implements GrantedAuthority {
    private final String authority;

    public CustomGrantedAuthority(Role role) {
        // Prefix if not already present.
        if (!role.getValue().toUpperCase().startsWith("ROLE_")) {
            this.authority = "ROLE_" + role.getValue().toUpperCase();
        } else {
            this.authority = role.getValue().toUpperCase();
        }
    }

    @Override
    public String getAuthority() {
        return authority;
    }
}


