package org.example.authservice.models;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "email_audit_log")
public class EmailAuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String toEmail;
    private String subject;
    private String status;
    private String provider;
    private LocalDateTime sentAt;

    @Column(columnDefinition = "TEXT")
    private String errorMessage;

    public EmailAuditLog() {}

    public EmailAuditLog(String toEmail, String subject, String status, String provider, String errorMessage) {
        this.toEmail = toEmail;
        this.subject = subject;
        this.status = status;
        this.provider = provider;
        this.sentAt = LocalDateTime.now();
        this.errorMessage = errorMessage;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getToEmail() {
        return toEmail;
    }

    public void setToEmail(String toEmail) {
        this.toEmail = toEmail;
    }

    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getProvider() {
        return provider;
    }

    public void setProvider(String provider) {
        this.provider = provider;
    }

    public LocalDateTime getSentAt() {
        return sentAt;
    }

    public void setSentAt(LocalDateTime sentAt) {
        this.sentAt = sentAt;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }
}
