package com.enterprise.iam.repository;

import com.enterprise.iam.entity.MfaSecret;
import com.enterprise.iam.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface MfaSecretRepository extends JpaRepository<MfaSecret, Long> {

    Optional<MfaSecret> findByUser(User user);
}
