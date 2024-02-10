package com.hit.community.dto;


import com.hit.community.entity.LoginType;
import com.hit.community.entity.Member;
import com.hit.community.entity.Role;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;


public record SignUpRequest(


        @NotBlank(message = "이름을 입력해주세요.")
        String name,
        @NotBlank(message = "이메일을 입력해주세요.")
        @Email(message = "유효한 이메일 형식이 아닙니다.")
        String email,

        String profile,
        @NotBlank(message = "비밀번호를 입력해주세요.")
        @Pattern(regexp = "(?=.*[0-9])(?=.*[a-zA-Z])(?=.*\\W)(?=\\S+$).{8,16}", message = "비밀번호는 8~16자 영문 대 소문자, 숫자, 특수문자를 사용해 주세요.")
        String password,
        @NotBlank(message = "학번을 입력해주세요.")
        String studentId,
        @NotBlank(message = "닉네임을 입력해주세요.")
        String nickName,
        String gender,
        @NotBlank(message = "전공을 입력해주세요.")
        String major
) {


    public static SignUpRequest of(
            String name,
            String email,
            String profile,
            String password,
            String studentId,
            String nickName,
            String gender,
            String major
    ){
        return new SignUpRequest(name, email, profile, password, studentId, nickName, gender, major);
    }


    public Member toEntity(String password, LoginType type) {
        return Member.builder()
                .name(name)
                .email(email)
                .profile(profile)
                .password(password)
                .studentId(studentId)
                .nickName(nickName)
                .gender(gender)
                .major(major)
                .role(Role.ROLE_USER)
                .type(type)
                .build();
    }


}
