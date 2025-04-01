package org.example.authservice.configs;


import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "rbac")
public class RbacProperties {
    /**
     * The default role applied to all new users.
     */
    private String defaultRole = "CUSTOMER";

    public String getDefaultRole() {
        return defaultRole;
    }

    public void setDefaultRole(String defaultRole) {
        this.defaultRole = defaultRole;
    }
}
