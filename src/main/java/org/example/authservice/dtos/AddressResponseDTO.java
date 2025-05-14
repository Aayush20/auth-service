package org.example.authservice.dtos;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Address details stored for user")
public class AddressResponseDTO {

    @Schema(description = "Address ID", example = "12")
    private Long id;

    @Schema(description = "Street", example = "221B Baker Street")
    private String street;

    @Schema(description = "City", example = "London")
    private String city;

    @Schema(description = "State", example = "Greater London")
    private String state;

    @Schema(description = "Country", example = "United Kingdom")
    private String country;

    @Schema(description = "Zip code", example = "NW1 6XE")
    private String zip;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getStreet() {
        return street;
    }

    public void setStreet(String street) {
        this.street = street;
    }

    public String getCity() {
        return city;
    }

    public void setCity(String city) {
        this.city = city;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public String getCountry() {
        return country;
    }

    public void setCountry(String country) {
        this.country = country;
    }

    public String getZip() {
        return zip;
    }

    public void setZip(String zip) {
        this.zip = zip;
    }

}

