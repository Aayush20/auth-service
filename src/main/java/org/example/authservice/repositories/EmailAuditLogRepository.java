package org.example.authservice.repositories;

import org.example.authservice.models.EmailAuditLog;
import org.springframework.data.jpa.repository.JpaRepository;

public interface EmailAuditLogRepository extends JpaRepository<EmailAuditLog, Long> {
}
