package org.example.authservice.controllers;

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
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/profile")
public class ProfileController {

    @Autowired
    private UserService userService;

    @Autowired
    private AddressService addressService;

    // Return the profile data for the current user.
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

    // Helper method to get the current authenticated user details.
    private CustomUserDetails getCurrentUser() {
        return (CustomUserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    }
//    private CustomUserDetails getCurrentUser() {
//        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
//        if (principal instanceof Jwt jwt) {
//            // Extract the subject (or email) from the JWT claims
//            String email = jwt.getSubject();
//            // Optionally, load CustomUserDetails from the database using your UserService:
//            return userService.loadUserByEmail(email);
//        } else if (principal instanceof CustomUserDetails customUserDetails) {
//            return customUserDetails;
//        } else {
//            throw new IllegalStateException("User not authenticated");
//        }
//    }

}

