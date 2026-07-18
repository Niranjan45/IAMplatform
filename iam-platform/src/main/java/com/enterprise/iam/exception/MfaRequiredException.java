package com.enterprise.iam.exception;

/** Thrown during login when MFA is enabled but no/invalid OTP code was supplied. */
public class MfaRequiredException extends RuntimeException {
    public MfaRequiredException(String message) {
        super(message);
    }
}
