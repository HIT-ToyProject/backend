package com.hit.community.controller;

import com.hit.community.dto.SignUpOAuth2Response;
import com.hit.community.entity.LoginType;
import com.hit.community.service.MemberService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(SignUpController.class)
class SignUpControllerTest {

    @MockBean
    private MemberService memberService;
    @Autowired
    private MockMvc mvc;

    @WithMockUser(roles = "GUEST")
    @Test
    @DisplayName("[VIEW][GET] 소셜 로그인 회원가입 페이지 이동 테스트 - 성공 (이메일 로그인 타입 존재, 소셜 회원가입 페이지로 이동)")
    void oAuth2SignUpExistsEmailSuccessTest() throws Exception
    {

        SignUpOAuth2Response signUpOAuth2Response = createMemberResponse();
        //given
        given(memberService.getOAuth2Member(any(), any())).willReturn(signUpOAuth2Response);
        //when & then
        mvc.perform(
                get("/signUp")
                        .queryParam("email", "test@email.com")
                        .queryParam("type", LoginType.NAVER.name())
                        .contentType(MediaType.TEXT_HTML_VALUE)
        )
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.TEXT_HTML_VALUE))
                .andExpect(view().name("oAuth2SignUp"))
                .andExpect(model().attribute("member", signUpOAuth2Response));
        then(memberService).should().getOAuth2Member(any(), any());
    }
    @WithMockUser(roles = "GUEST")
    @Test
    @DisplayName("[VIEW][GET] 일반 로그인 회원가입 페이지 이동 테스트 - 성공 (이메일, type x, 일반 회원가입 페이지로 이동)")
    void signUpNotExistsEmailSuccessTest() throws Exception
    {
        //given
        //when & then
        mvc.perform(
                get("/signUp")
                        .contentType(MediaType.TEXT_HTML_VALUE)
        )
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.TEXT_HTML_VALUE))
                .andExpect(view().name("signUp"));
    }

    private static SignUpOAuth2Response createMemberResponse() {
        return SignUpOAuth2Response.of(
                "name",
                "email@naver.com",
                "profile"
        );
    }
}