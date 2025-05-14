package org.example.authservice.dtos;


import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

@Schema(description = "DTO for creating or updating an address")
public class AddressRequestDTO {

    @NotBlank
    @Schema(description = "Street address", example = "221B Baker Street")
    private String street;

    @NotBlank
    @Schema(description = "City", example = "London")
    private String city;

    @NotBlank
    @Schema(description = "State", example = "Greater London")
    private String state;

    @NotBlank
    @Schema(description = "Country", example = "United Kingdom")
    private String country;

    @NotBlank
    @Schema(description = "Zip/postal code", example = "NW1 6XE")
    private String zip;

    public @NotBlank String getStreet() {
        return street;
    }

    public void setStreet(@NotBlank String street) {
        this.street = street;
    }

    public @NotBlank String getZip() {
        return zip;
    }

    public void setZip(@NotBlank String zip) {
        this.zip = zip;
    }

    public @NotBlank String getCountry() {
        return country;
    }

    public void setCountry(@NotBlank String country) {
        this.country = country;
    }

    public @NotBlank String getState() {
        return state;
    }

    public void setState(@NotBlank String state) {
        this.state = state;
    }

    public @NotBlank String getCity() {
        return city;
    }

    public void setCity(@NotBlank String city) {
        this.city = city;
    }

}

