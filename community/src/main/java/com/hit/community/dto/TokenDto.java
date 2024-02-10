package com.hit.community.dto;

import com.hit.community.entity.RefreshToken;
import com.hit.community.properties.JwtProperties;

public record TokenDto(
        String accessToken,
        String refreshToken,
        String email

) {

    public static TokenDto of(
            String accessToken,
            String refreshToken,
            String email
    ){
        return new TokenDto(accessToken, refreshToken, email);
    }


    public RefreshToken toRefreshTokenEntity(){
        return RefreshToken.builder()
                .email(email)
                .refreshToken(refreshToken)
                .build();
    }
}
