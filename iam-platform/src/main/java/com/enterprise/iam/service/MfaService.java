package com.enterprise.iam.service;

import com.enterprise.iam.dto.response.MfaSetupResponse;
import com.enterprise.iam.entity.MfaSecret;
import com.enterprise.iam.entity.User;
import com.enterprise.iam.repository.MfaSecretRepository;
import com.enterprise.iam.repository.UserRepository;
import com.enterprise.iam.util.QrCodeGenerator;
import com.enterprise.iam.util.TotpUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class MfaService {

    private final MfaSecretRepository mfaSecretRepository;
    private final UserRepository userRepository;
    private final TotpUtil totpUtil;
    private final QrCodeGenerator qrCodeGenerator;

    @Value("${app.jwt.issuer}")
    private String issuer;

    /** Step 1 of enabling MFA: generate a secret and return a QR code, but don't enable MFA yet. */
    @Transactional
    public MfaSetupResponse setupMfa(User user) {
        String secret = totpUtil.generateSecret();

        MfaSecret mfaSecret = mfaSecretRepository.findByUser(user)
                .map(existing -> {
                    existing.setSecret(secret);
                    existing.setConfirmed(false);
                    return existing;
                })
                .orElseGet(() -> MfaSecret.builder()
                        .user(user)
                        .secret(secret)
                        .confirmed(false)
                        .createdAt(LocalDateTime.now())
                        .build());

        mfaSecretRepository.save(mfaSecret);

        String otpAuthUrl = totpUtil.buildOtpAuthUrl(secret, user.getEmail(), issuer);
        String qrCodeDataUri = qrCodeGenerator.generateDataUri(otpAuthUrl);

        return new MfaSetupResponse(secret, qrCodeDataUri, otpAuthUrl);
    }

    /** Step 2: user submits a code from their authenticator app to confirm and activate MFA. */
    @Transactional
    public void confirmMfa(User user, String code) {
        MfaSecret mfaSecret = mfaSecretRepository.findByUser(user)
                .orElseThrow(() -> new IllegalStateException("MFA setup has not been initiated for this user"));

        if (!totpUtil.verifyCode(mfaSecret.getSecret(), code)) {
            throw new IllegalArgumentException("Invalid or expired verification code");
        }

        mfaSecret.setConfirmed(true);
        mfaSecretRepository.save(mfaSecret);

        user.setMfaEnabled(true);
        userRepository.save(user);
    }

    @Transactional
    public void disableMfa(User user) {
        mfaSecretRepository.findByUser(user).ifPresent(mfaSecretRepository::delete);
        user.setMfaEnabled(false);
        userRepository.save(user);
    }

    public boolean verifyCode(User user, String code) {
        return mfaSecretRepository.findByUser(user)
                .filter(MfaSecret::isConfirmed)
                .map(secret -> totpUtil.verifyCode(secret.getSecret(), code))
                .orElse(false);
    }
}
