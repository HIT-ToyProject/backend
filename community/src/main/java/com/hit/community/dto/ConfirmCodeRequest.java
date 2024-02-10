package com.hit.community.dto;

public record ConfirmCodeRequest(
        String email,
        String confirmCode
) {

    public static ConfirmCodeRequest of(
            String email,
            String confirmCode
    ){
        return new ConfirmCodeRequest(email, confirmCode);
    }
}
