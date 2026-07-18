package com.enterprise.iam.repository;

import com.enterprise.iam.entity.User;
import com.enterprise.iam.entity.UserSession;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface UserSessionRepository extends JpaRepository<UserSession, Long> {

    List<UserSession> findAllByUserAndActiveTrue(User user);

    Optional<UserSession> findBySessionTokenAndActiveTrue(String sessionToken);

    @Modifying
    @Query("update UserSession s set s.active = false where s.user = :user")
    void deactivateAllByUser(@Param("user") User user);

    @Modifying
    @Query("update UserSession s set s.active = false where s.sessionToken = :token")
    void deactivateByToken(@Param("token") String token);
}
