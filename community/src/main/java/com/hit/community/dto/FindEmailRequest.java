package com.hit.community.dto;

import jakarta.validation.constraints.NotBlank;

public record FindEmailRequest(

        @NotBlank(message = "이름과 학번은 공백일 수 없습니다.")
        String name,

        @NotBlank(message = "이름과 학번은 공백일 수 없습니다.")
        String studentId
) {

    public static FindEmailRequest of(
            String name,
            String studentId
    ){
        return new FindEmailRequest(name, studentId);
    }
}
