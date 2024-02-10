package com.hit.community.controller.api;

import jakarta.validation.constraints.NotBlank;

public record SignUpOAuth2Request(
        String name,
        String email,

        String profile,
        @NotBlank(message = "학번을 입력해주세요.")
        String studentId,
        @NotBlank(message = "닉네임을 입력해주세요.")
        String nickName,
        String gender,
        @NotBlank(message = "전공을 입력해주세요.")
        String major
) {

    public static SignUpOAuth2Request of(
            String name,
            String email,
            String profile,
            String studentId,
            String nickName,
            String gender,
            String major
    ){
        return new SignUpOAuth2Request(name, email, profile, studentId, nickName, gender, major);
    }
}
