package org.example.authservice.controllers;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.example.authservice.dtos.AddressMapper;
import org.example.authservice.dtos.AddressRequestDTO;
import org.example.authservice.dtos.AddressResponseDTO;
import org.example.authservice.models.Address;
import org.example.authservice.security.models.CustomUserDetails;
import org.example.authservice.services.AddressService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

@Tag(name = "User - Address Management")
@RestController
@RequestMapping("/api/address")
public class AddressController {

    @Autowired
    private AddressService addressService;

    @Operation(summary = "Get all addresses for authenticated user")
    @ApiResponse(responseCode = "200", description = "List of addresses returned")
    @GetMapping
    public ResponseEntity<List<AddressResponseDTO>> getAddresses() {
        CustomUserDetails userDetails = getCurrentUser();
        Long userId = userDetails.getUser().getId();
        List<Address> addresses = addressService.getAddressesForUser(userId);
        List<AddressResponseDTO> response = addresses.stream()
                .map(AddressMapper::toDTO)
                .collect(Collectors.toList());
        return ResponseEntity.ok(response);
    }

    @Operation(summary = "Add new address for authenticated user")
    @ApiResponse(responseCode = "201", description = "Address added successfully")
    @PostMapping
    public ResponseEntity<AddressResponseDTO> addAddress(@RequestBody AddressRequestDTO addressDto) {
        CustomUserDetails userDetails = getCurrentUser();
        Long userId = userDetails.getUser().getId();
        Address address = AddressMapper.toEntity(addressDto);
        Address savedAddress = addressService.addAddressToUser(userId, address);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(AddressMapper.toDTO(savedAddress));
    }

    @Operation(summary = "Update address by ID")
    @ApiResponse(responseCode = "200", description = "Address updated successfully")
    @PutMapping("/{addressId}")
    public ResponseEntity<AddressResponseDTO> updateAddress(@PathVariable Long addressId,
                                                            @RequestBody AddressRequestDTO addressDto) {
        Address updated = addressService.updateAddress(addressId, AddressMapper.toEntity(addressDto));
        return ResponseEntity.ok(AddressMapper.toDTO(updated));
    }

    @Operation(summary = "Delete address by ID")
    @ApiResponse(responseCode = "200", description = "Address deleted")
    @DeleteMapping("/{addressId}")
    public ResponseEntity<Void> deleteAddress(@PathVariable Long addressId) {
        addressService.deleteAddress(addressId);
        return ResponseEntity.ok().build();
    }

    private CustomUserDetails getCurrentUser() {
        return (CustomUserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    }
}
