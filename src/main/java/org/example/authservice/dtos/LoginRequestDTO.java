package org.example.authservice.dtos;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

@Schema(description = "User login request payload")
public class LoginRequestDTO {

    @NotBlank
    @Schema(description = "Email address", example = "user@example.com")
    private String email;

    @NotBlank
    @Schema(description = "Password", example = "secret123")
    private String password;

    public @NotBlank String getEmail() {
        return email;
    }

    public void setEmail(@NotBlank String email) {
        this.email = email;
    }

    public @NotBlank String getPassword() {
        return password;
    }

    public void setPassword(@NotBlank String password) {
        this.password = password;
    }
}

