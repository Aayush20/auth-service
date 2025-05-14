package org.example.authservice.controllers;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.example.authservice.dtos.AddressMapper;
import org.example.authservice.dtos.AddressResponseDTO;
import org.example.authservice.dtos.UserProfileDTO;
import org.example.authservice.models.Address;
import org.example.authservice.models.User;
import org.example.authservice.security.models.CustomUserDetails;
import org.example.authservice.services.AddressService;
import org.example.authservice.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

@Tag(name = "User - Profile API")
@RestController
@RequestMapping("/api/profile")
public class ProfileController {

    @Autowired private UserService userService;
    @Autowired private AddressService addressService;

    @Operation(summary = "Get current authenticated user's profile")
    @GetMapping
    public ResponseEntity<UserProfileDTO> getUserProfile() {
        CustomUserDetails userDetails = getCurrentUser();
        User user = userDetails.getUser();

        UserProfileDTO profile = new UserProfileDTO();
        profile.setUserId(user.getId());
        profile.setName(user.getName());
        profile.setEmail(user.getEmail());
        profile.setPhoneNumber(user.getPhoneNumber());

        List<Address> addresses = addressService.getAddressesForUser(user.getId());
        List<AddressResponseDTO> addressDTOs = addresses.stream()
                .map(AddressMapper::toDTO)
                .collect(Collectors.toList());
        profile.setAddresses(addressDTOs);

        return ResponseEntity.ok(profile);
    }

    private CustomUserDetails getCurrentUser() {
        return (CustomUserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    }
}
