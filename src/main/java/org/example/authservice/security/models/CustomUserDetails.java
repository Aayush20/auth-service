package org.example.authservice.security.models;

import org.example.authservice.models.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import java.util.Collection;
import java.util.stream.Collectors;

public class CustomUserDetails implements UserDetails {

    private final User user;

    public CustomUserDetails(User user) {
        this.user = user;
    }

    /**
     * Returns authorities ensuring that every role is prefixed with "ROLE_"
     * so that method-level security (e.g., with @PreAuthorize) works as expected.
     */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return user.getRoles().stream()
                .map(role -> {
                    String roleValue = role.getValue();
                    if (!roleValue.startsWith("ROLE_")) {
                        roleValue = "ROLE_" + roleValue;
                    }
                    return new SimpleGrantedAuthority(roleValue);
                })
                .collect(Collectors.toList());
    }

    @Override
    public String getPassword() {
        return user.getHashedPassword();
    }

    @Override
    public String getUsername() {
        return user.getEmail();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

//    @Override
//    public boolean isEnabled() {
//        // Typically, enabled status might depend on other factors.
//        return user.isEmailVerified();
//    }
    @Override
    public boolean isEnabled() {
        return true;
    }


    // Provide access to the underlying User if needed.
    public User getUser() {
        return user;
    }
}
