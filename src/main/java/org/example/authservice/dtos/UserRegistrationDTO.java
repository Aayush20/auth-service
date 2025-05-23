package org.example.authservice.dtos;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import java.util.Set;
import org.example.authservice.models.Scope;

@Schema(description = "User registration request payload")
public class UserRegistrationDTO {

    @NotBlank
    @Schema(description = "Full name", example = "Aayush Kumar")
    private String name;

    @Email
    @NotBlank
    @Schema(description = "Email address", example = "aayush@example.com")
    private String email;

    @NotBlank
    @Schema(description = "Password", example = "StrongPassword123!")
    private String password;

    @NotBlank
    @Schema(description = "Phone number", example = "9876543210")
    private String phoneNumber;

    @Schema(description = "User scopes", example = "[\"READ_PRODUCTS\", \"WRITE_ORDER\"]")
    private Set<Scope> scopes;

    // Getters and Setters
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }

    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }

    public String getPhoneNumber() { return phoneNumber; }
    public void setPhoneNumber(String phoneNumber) { this.phoneNumber = phoneNumber; }

    public Set<Scope> getScopes() {
        return scopes;
    }

    public void setScopes(Set<Scope> scopes) {
        this.scopes = scopes;
    }
}
