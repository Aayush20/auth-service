package org.example.authservice.services;

import com.sendgrid.*;
import com.sendgrid.helpers.mail.Mail;
import com.sendgrid.helpers.mail.objects.Content;
import com.sendgrid.helpers.mail.objects.Email;
import freemarker.template.Template;
import io.micrometer.core.instrument.MeterRegistry;
import org.example.authservice.models.EmailAuditLog;
import org.example.authservice.repositories.EmailAuditLogRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.ui.freemarker.FreeMarkerTemplateUtils;

import java.io.IOException;
import java.util.Map;

@Service
public class SendGridEmailService {
    private static final Logger logger = LoggerFactory.getLogger(SendGridEmailService.class);

    @Value("${sendgrid.api-key}")
    private String sendgridApiKey;

    @Value("${sendgrid.sender-email}")
    private String senderEmail;

    @Value("${sendgrid.sender-name}")
    private String senderName;

    @Autowired private EmailAuditLogRepository auditLogRepository;

    @Autowired
    private freemarker.template.Configuration freemarkerConfig;

    @Autowired
    private MeterRegistry meterRegistry;

    public void sendEmail(String to, String subject, String content) throws IOException {
        Email from = new Email(senderEmail, senderName);
        Email toEmail = new Email(to);
        Content emailContent = new Content("text/plain", content);
        Mail mail = new Mail(from, subject, toEmail, emailContent);

        SendGrid sg = new SendGrid(sendgridApiKey);
        Request request = new Request();
        try {
            request.setMethod(Method.POST);
            request.setEndpoint("mail/send");
            request.setBody(mail.build());
            Response response = sg.api(request);

            if (response.getStatusCode() >= 400) {
                meterRegistry.counter("emails.failed.total").increment();
                throw new RuntimeException("Failed to send email: " + response.getBody());
            }
            meterRegistry.counter("emails.sent.total").increment();
            logger.info("📧 Email sent to {} | Status: {}", toEmail, response.getStatusCode());
            auditLogRepository.save(new EmailAuditLog(to, subject, "SENT", "sendgrid", null));
        } catch (IOException e) {
            meterRegistry.counter("emails.failed.total").increment();
            auditLogRepository.save(new EmailAuditLog(to, subject, "FAILED", "sendgrid", e.getMessage()));
            throw new IOException("Error sending email via SendGrid", e);
        }
    }


    public void sendTemplatedEmail(String to, String subject, String templateName, Map<String, Object> model) throws IOException {
        Email from = new Email(senderEmail, senderName);
        Email toEmail = new Email(to);

        try {
            Template template = freemarkerConfig.getTemplate("email/" + templateName + ".ftl");
            String html = FreeMarkerTemplateUtils.processTemplateIntoString(template, model);

            Mail mail = new Mail(from, subject, toEmail, new Content("text/html", html));

            SendGrid sg = new SendGrid(sendgridApiKey);
            Request request = new Request();
            request.setMethod(Method.POST);
            request.setEndpoint("mail/send");
            request.setBody(mail.build());

            Response response = sg.api(request);
            if (response.getStatusCode() >= 400) {
                meterRegistry.counter("emails.failed.total").increment();
                throw new RuntimeException("Failed to send email: " + response.getBody());
            }

            meterRegistry.counter("emails.sent.total").increment();
            logger.info("📧 Templated email sent to {} | Status: {}", to, response.getStatusCode());
            auditLogRepository.save(new EmailAuditLog(to, subject, "SENT", "sendgrid", null));

        } catch (Exception e) {
            meterRegistry.counter("emails.failed.total").increment();
            logger.error("❌ Email template error: {}", e.getMessage());
            auditLogRepository.save(new EmailAuditLog(to, subject, "FAILED", "sendgrid", e.getMessage()));
            throw new IOException("Template rendering failed", e);
        }
    }
}
