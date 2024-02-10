package com.hit.community.controller.api;

import com.hit.community.error.ErrorCode;
import com.hit.community.properties.JwtProperties;
import com.hit.community.service.MemberService;
import jakarta.servlet.http.Cookie;
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
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;


@WebMvcTest(controllers = LogoutApiController.class)
class LogoutApiControllerTest {

    @MockBean
    private MemberService memberService;

    @Autowired
    private MockMvc mvc;


    // url 경로 테스트 수정
    @WithMockUser(roles = "USER")
    @Test
    @DisplayName("[API][POST] 로그아웃 테스트 - 성공")
    void logoutSuccessTest() throws Exception
    {
        //given
        Cookie cookie = new Cookie(JwtProperties.REFRESH_TOKEN_NAME, "testRefreshToken");
        given(memberService.logout(any())).willReturn(true);
        //when & then
        mvc.perform(post("/logout/proc")
                        .header(JwtProperties.AUTHORIZATION, JwtProperties.JWT_TYPE+"testAccessToken")
                        .cookie(cookie)
                        .contentType(MediaType.APPLICATION_JSON_VALUE)
                        .with(csrf())
        )
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.errorCode").value(ErrorCode.OK.getStatusCode().value()))
                .andExpect(jsonPath("$.message").value(ErrorCode.OK.getMessage()))
                .andExpect(jsonPath("$.data").value(true));

        then(memberService).should().logout(any());

    }

}