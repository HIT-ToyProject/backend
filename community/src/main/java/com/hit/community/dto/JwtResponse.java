package com.hit.community.dto;

public record JwtResponse(
        String email,
        String accessToken
) {
    public static JwtResponse of(
            String email,
            String accessToken
    ){
        return new JwtResponse(email, accessToken);
    }
}
