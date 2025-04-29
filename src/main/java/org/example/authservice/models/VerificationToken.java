package org.example.authservice.models;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

@Entity
@Table(
        name = "verification_tokens",
        indexes = @Index(name = "idx_verification_expiry", columnList = "expiry_date")
)
@Getter @Setter @NoArgsConstructor
public class VerificationToken extends BaseModel {
    @Column(nullable = false, unique = true)
    private String token;

    @Column(name = "expiry_date", nullable = false)
    private Instant expiryDate;

    @OneToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    public VerificationToken(User user, String token, long durationHours) {
        this.user = user;
        this.token = token;
        this.expiryDate = Instant.now().plus(durationHours, ChronoUnit.HOURS);
    }
}
