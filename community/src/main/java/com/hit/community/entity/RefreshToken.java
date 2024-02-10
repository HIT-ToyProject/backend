package com.hit.community.entity;

import com.hit.community.dto.TokenDto;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.data.redis.core.RedisHash;
import org.springframework.data.redis.core.index.Indexed;

import java.io.Serializable;

@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Getter
@RedisHash(value = "Refresh_token", timeToLive = 1000 * 60 * 60 * 24 * 14)
public class RefreshToken {

    @Id
    private Long id;

    @Indexed
    private String refreshToken;
    private String email;

    @Builder
    public RefreshToken(String refreshToken, String email) {
        this.refreshToken = refreshToken;
        this.email = email;
    }

    public void updateEntity(TokenDto tokenDto){
        this.refreshToken  = tokenDto.refreshToken();
        this.email = tokenDto.email();
    }
}
