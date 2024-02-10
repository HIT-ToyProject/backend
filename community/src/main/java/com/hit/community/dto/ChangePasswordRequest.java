package com.hit.community.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record ChangePasswordRequest(
        String email,
        @NotBlank(message = "비밀번호를 입력해 주세요.")
        @Pattern(regexp = "(?=.*[0-9])(?=.*[a-zA-Z])(?=.*\\W)(?=\\S+$).{8,16}", message = "비밀번호는 8~16자 영문 대 소문자, 숫자, 특수문자를 사용해 주세요.")
        String newPassword
) {
    public static ChangePasswordRequest of(String email, String newPassword){
        return new ChangePasswordRequest(email, newPassword);
    }
}
