package org.example.authservice.dtos;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import org.example.authservice.models.Address;
import java.util.List;

@Data
@Schema(name = "UserProfile", description = "User profile info with address list")
public class UserProfileDTO {

    @Schema(description = "User ID", example = "101")
    private Long userId;

    @Schema(description = "Full name of the user", example = "Aayush Kumar")
    private String name;

    @Schema(description = "Email address", example = "aayush@example.com")
    private String email;

    @Schema(description = "Phone number", example = "9876543210")
    private String phoneNumber;

    @Schema(description = "List of user's saved addresses")
    private List<AddressResponseDTO> addresses;

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPhoneNumber() {
        return phoneNumber;
    }

    public void setPhoneNumber(String phoneNumber) {
        this.phoneNumber = phoneNumber;
    }

    public List<AddressResponseDTO> getAddresses() {
        return addresses;
    }

    public void setAddresses(List<AddressResponseDTO> addresses) {
        this.addresses = addresses;
    }
}
