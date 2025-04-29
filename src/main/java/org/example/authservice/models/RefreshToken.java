package org.example.authservice.models;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

@Entity
@Table(
        name = "refresh_tokens",
        indexes = @Index(name = "idx_refresh_expiry", columnList = "expiry_date")
)
@Getter @Setter @NoArgsConstructor
public class RefreshToken extends BaseModel {
    @OneToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(nullable = false, unique = true)
    private String token;

    @Column(name = "expiry_date", nullable = false)
    private Instant expiryDate;

    @Column(nullable = false)
    private boolean revoked = false;

    private Instant revokedAt;

    public RefreshToken(User user, String token, long durationMinutes) {
        this.user = user;
        this.token = token;
        this.expiryDate = Instant.now().plus(durationMinutes, ChronoUnit.MINUTES);
    }
}
