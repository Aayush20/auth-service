package org.example.authservice.dtos;

import org.springframework.context.ApplicationEvent;

import java.util.List;

public class UserRegisteredEvent  extends ApplicationEvent {
    private Long userId;
    private String email;
    private List<String> roles;

    public UserRegisteredEvent(Object source, Long userId, String email, List<String> roles) {
        super(source);
        this.userId = userId;
        this.email = email;
        this.roles = roles;
    }

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public List<String> getRoles() {
        return roles;
    }

    public void setRoles(List<String> roles) {
        this.roles = roles;
    }
}
