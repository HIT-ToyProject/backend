package com.hit.community.dto;

import org.springframework.http.client.reactive.ClientHttpRequest;
import org.springframework.web.reactive.function.BodyInserter;

public record CustomTokenResponse(
        String accessToken,
        String refreshToken
) {

    public static CustomTokenResponse of(
            String accessToken,
            String refreshToken
    ){
        return new CustomTokenResponse(accessToken, refreshToken);
    }

    public static CustomTokenResponse fromResponse(
            TokenDto tokenDto
    ){
        return CustomTokenResponse.of(tokenDto.accessToken(), tokenDto.refreshToken());
    }
}
