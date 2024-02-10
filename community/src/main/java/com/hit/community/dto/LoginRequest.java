package com.hit.community.dto;

import jakarta.validation.constraints.NotBlank;

public record LoginRequest(
          @NotBlank(message = "이메일 또는 비밀번호를 입력해주세요.")
          String email,
          @NotBlank(message = "이메일 또는 비밀번호를 입력해주세요.")
          String password
) {

    public static LoginRequest of(
            String email,
            String password
    ){
        return new LoginRequest(email, password);
    }
}
