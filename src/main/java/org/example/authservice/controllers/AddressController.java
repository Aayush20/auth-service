//package org.example.authservice.controllers;
//
//import org.example.authservice.models.Address;
//import org.example.authservice.services.AddressService;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.http.ResponseEntity;
//import org.springframework.web.bind.annotation.*;
//
//import java.util.List;
//
//@RestController
//@RequestMapping("/api/address")
//public class AddressController {
//
//    @Autowired
//    private AddressService addressService;
//
//    // Get all addresses for a given user (Note: In production, retrieve userId from auth context)
//    @GetMapping("/{userId}")
//    public ResponseEntity<List<Address>> getAddresses(@PathVariable Long userId) {
//        List<Address> addresses = addressService.getAddressesForUser(userId);
//        return ResponseEntity.ok(addresses);
//    }
//
//    // Add a new address for a user.
//    @PostMapping("/{userId}")
//    public ResponseEntity<Address> addAddress(@PathVariable Long userId, @RequestBody Address address) {
//        Address saved = addressService.addAddressToUser(userId, address);
//        return ResponseEntity.ok(saved);
//    }
//
//    // Update an existing address.
//    @PutMapping("/{addressId}")
//    public ResponseEntity<Address> updateAddress(@PathVariable Long addressId, @RequestBody Address address) {
//        Address updated = addressService.updateAddress(addressId, address);
//        return ResponseEntity.ok(updated);
//    }
//
//    // Delete an address.
//    @DeleteMapping("/{addressId}")
//    public ResponseEntity<Void> deleteAddress(@PathVariable Long addressId) {
//        addressService.deleteAddress(addressId);
//        return ResponseEntity.ok().build();
//    }
//}
//    //the code for securing the endpoints
//    //(for example by extracting the currently authenticated user from the security context rather than passing a userId in the URL)
//    //In production, you generally want to obtain the authenticated user from the security context
//    // so that you know which user is performing the action without trusting a URL‑supplied identifier.
//    // Using Spring Security, you can retrieve the currently authenticated principal (here, our custom CustomUserDetails) from the SecurityContextHolder
//
//

package org.example.authservice.controllers;

import org.example.authservice.dtos.AddressMapper;
import org.example.authservice.dtos.AddressRequestDTO;
import org.example.authservice.dtos.AddressResponseDTO;
import org.example.authservice.models.Address;
import org.example.authservice.security.models.CustomUserDetails;
import org.example.authservice.services.AddressService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/address")
public class AddressController {

    @Autowired
    private AddressService addressService;

    // Get addresses for the currently authenticated user.
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

    // Add a new address for the currently authenticated user.
    @PostMapping
    public ResponseEntity<AddressResponseDTO> addAddress(@RequestBody AddressRequestDTO addressDto) {
        CustomUserDetails userDetails = getCurrentUser();
        Long userId = userDetails.getUser().getId();
        Address address = AddressMapper.toEntity(addressDto);
        Address savedAddress = addressService.addAddressToUser(userId, address);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(AddressMapper.toDTO(savedAddress));
    }

    // Update an existing address.
    @PutMapping("/{addressId}")
    public ResponseEntity<AddressResponseDTO> updateAddress(@PathVariable Long addressId,
                                                            @RequestBody AddressRequestDTO addressDto) {
        // Ownership check should be done in the service layer.
        Address updated = addressService.updateAddress(addressId, AddressMapper.toEntity(addressDto));
        return ResponseEntity.ok(AddressMapper.toDTO(updated));
    }

    // Delete an address.
    @DeleteMapping("/{addressId}")
    public ResponseEntity<Void> deleteAddress(@PathVariable Long addressId) {
        addressService.deleteAddress(addressId);
        return ResponseEntity.ok().build();
    }

    // Helper method to get the current authenticated user details.
    private CustomUserDetails getCurrentUser() {
        return (CustomUserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    }
}


