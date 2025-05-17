
package org.example.authservice.configs;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
@ConfigurationProperties(prefix = "auth")
public class AuthValidationProperties {
    private List<String> internalAllowedSubjects;

    public List<String> getInternalAllowedSubjects() {
        return internalAllowedSubjects;
    }

    public void setInternalAllowedSubjects(List<String> internalAllowedSubjects) {
        this.internalAllowedSubjects = internalAllowedSubjects;
    }
}
