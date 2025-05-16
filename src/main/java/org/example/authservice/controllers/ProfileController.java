package org.example.authservice.controllers;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
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
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/profile")
@Tag(name = "User - Profile API")
public class ProfileController {

    @Autowired private UserService userService;
    @Autowired private AddressService addressService;

    @Operation(summary = "Get current authenticated user's full profile")
    @PreAuthorize("hasAuthority('SCOPE_profile.read')")
    @GetMapping
    public ResponseEntity<UserProfileDTO> getUserProfile() {
        CustomUserDetails userDetails = (CustomUserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
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

    @GetMapping("/me")
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "Get current user claims", security = @SecurityRequirement(name = "bearerAuth"))
    @ApiResponse(
            responseCode = "200",
            description = "Current authenticated user's JWT claims",
            content = @Content(mediaType = "application/json",
                    examples = @ExampleObject(value = """
            {
              "userId": "1",
              "username": "aayush@example.com",
              "roles": ["USER"],
              "scopes": ["profile.read", "profile.write"],
              "emailVerified": true
            }
            """))
    )
    public ResponseEntity<Map<String, Object>> getCurrentUser(@AuthenticationPrincipal Jwt jwt) {
        Map<String, Object> userInfo = new HashMap<>();
        userInfo.put("userId", jwt.getSubject());
        userInfo.put("username", jwt.getClaimAsString("email"));
        userInfo.put("roles", jwt.getClaimAsStringList("roles"));
        userInfo.put("scopes", jwt.getClaimAsStringList("scope"));
        userInfo.put("emailVerified", jwt.getClaim("email_verified"));
        return ResponseEntity.ok(userInfo);
    }
}

