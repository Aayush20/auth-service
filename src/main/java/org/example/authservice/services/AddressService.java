package org.example.authservice.services;

import jakarta.transaction.Transactional;
import org.example.authservice.models.Address;
import org.example.authservice.models.User;
import org.example.authservice.repositories.AddressRepository;
import org.example.authservice.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.util.List;

@Service
public class AddressService {

    @Autowired
    private AddressRepository addressRepository;

    @Autowired
    private UserRepository userRepository;

    // List all addresses for a specific user.
    public List<Address> getAddressesForUser(Long userId) {
        return addressRepository.findByUserId(userId);
    }

    // Add a new address for the user.
    @Transactional
    public Address addAddressToUser(Long userId, Address address) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
        address.setUser(user);
        return addressRepository.save(address);
    }

    // Update an existing address.
    @Transactional
    public Address updateAddress(Long addressId, Address updatedAddress) {
        Address existing = addressRepository.findById(addressId)
                .orElseThrow(() -> new IllegalArgumentException("Address not found"));
        existing.setStreet(updatedAddress.getStreet());
        existing.setCity(updatedAddress.getCity());
        existing.setState(updatedAddress.getState());
        existing.setCountry(updatedAddress.getCountry());
        existing.setZip(updatedAddress.getZip());
        return addressRepository.save(existing);
    }

    // Delete an address.
    @Transactional
    public void deleteAddress(Long addressId) {
        addressRepository.deleteById(addressId);
    }
}
