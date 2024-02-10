package com.hit.community.repository;

import com.hit.community.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;


public interface RefreshTokenRepository extends CrudRepository<RefreshToken, Long> {

        boolean existsByRefreshToken(String refreshToken);
        Optional<RefreshToken> findByRefreshToken(String refreshToken);


}
