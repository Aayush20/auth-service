package org.example.authservice.models;

import jakarta.persistence.*;

@Entity
@Table(name = "roles")
public class Role {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, unique = true)
    private RoleName value;

    public enum RoleName {
        USER,
        ADMIN,
        SERVICE
    }

    public Role() {}

    public Role(RoleName value) {
        this.value = value;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public RoleName getValue() {
        return value;
    }

    public void setValue(RoleName value) {
        this.value = value;
    }
}
