package org.example.authservice.models;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import jakarta.persistence.Entity;
import lombok.Getter;
import lombok.Setter;

@Entity
@Getter
@Setter
@JsonDeserialize(as = Role.class)
public class Role extends BaseModel {
    private String value;

    public Role(String roleUser) {
        super();
    }

    public Role() {

    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }
}

