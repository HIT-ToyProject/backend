package com.hit.community.dto;

import jakarta.validation.constraints.NotBlank;

public record CheckMemberRequest(
        
        @NotBlank(message = "이름과 이메일은 공백일 수 없습니다.")
        String name,

        @NotBlank(message = "이름과 이메일은 공백일 수 없습니다.")
        String email
) {

    public static CheckMemberRequest of(String name, String email){
        return new CheckMemberRequest(name, email);
    }
}
