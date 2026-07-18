package com.enterprise.iam.service;

import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

/**
 * Sends transactional emails (verification, password reset). Sending is async and
 * failures are logged rather than propagated, so a flaky SMTP provider never breaks
 * registration or password-reset flows for the user.
 */
@Service
@RequiredArgsConstructor
public class EmailService {

    private static final Logger log = LoggerFactory.getLogger(EmailService.class);

    private final JavaMailSender mailSender;

    @Value("${app.mail.from}")
    private String fromAddress;

    @Value("${app.mail.frontend-base-url}")
    private String frontendBaseUrl;

    @Async("taskExecutor")
    public void sendVerificationEmail(String toEmail, String token) {
        String link = frontendBaseUrl + "/verify-email?token=" + token;
        String body = "Welcome to Enterprise IAM Platform!\n\n"
                + "Please verify your email address by clicking the link below:\n" + link
                + "\n\nThis link expires in 24 hours. If you didn't create this account, please ignore this email.";
        sendEmail(toEmail, "Verify your email address", body);
    }

    @Async("taskExecutor")
    public void sendPasswordResetEmail(String toEmail, String token) {
        String link = frontendBaseUrl + "/reset-password?token=" + token;
        String body = "We received a request to reset your password.\n\n"
                + "Click the link below to choose a new password:\n" + link
                + "\n\nThis link expires in 30 minutes. If you didn't request this, you can safely ignore this email.";
        sendEmail(toEmail, "Reset your password", body);
    }

    @Async("taskExecutor")
    public void sendAccountLockedEmail(String toEmail) {
        String body = "Your account has been temporarily locked due to multiple failed login attempts.\n\n"
                + "It will automatically unlock after the lockout period, or you can reset your password to regain access immediately.";
        sendEmail(toEmail, "Your account has been locked", body);
    }

    private void sendEmail(String to, String subject, String body) {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(fromAddress);
            message.setTo(to);
            message.setSubject(subject);
            message.setText(body);
            mailSender.send(message);
        } catch (Exception e) {
            log.error("Failed to send email to {}: {}", to, e.getMessage());
        }
    }
}
