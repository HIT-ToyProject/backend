package com.hit.community.entity;

import jakarta.persistence.Id;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.data.redis.core.RedisHash;
import org.springframework.data.redis.core.index.Indexed;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@RedisHash(value = "Mail", timeToLive = 30 * 60 * 1000)
public class Mail {

    @Id
    private Long id;
    @Indexed
    private String toEmail;
    private String confirmCode;


    @Builder
    public Mail(String toEmail, String confirmCode) {
        this.toEmail = toEmail;
        this.confirmCode = confirmCode;
    }

    public Mail update(String confirmCode) {
        this.confirmCode = confirmCode;
        return this;
    }
}
