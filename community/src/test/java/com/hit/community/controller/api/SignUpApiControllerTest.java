package com.hit.community.controller.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.hit.community.dto.ConfirmCodeRequest;
import com.hit.community.dto.SignUpRequest;
import com.hit.community.entity.Member;
import com.hit.community.error.ErrorCode;
import com.hit.community.service.MemberService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.Objects;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;


@WebMvcTest(controllers = SignUpApiController.class)
class SignUpApiControllerTest {

    @MockBean
    private MemberService memberService;
    @Autowired
    private MockMvc mvc;
    @Autowired
    private ObjectMapper objectMapper;



    @WithMockUser(roles = "GUEST")
    @Test
    @DisplayName("[API][POST] 회원가입 테스트 - 성공")
    void singUpSuccessTest() throws Exception
    {
        String email = "email@naver.com";
        SignUpRequest signUpRequest = createMemberRequest(email);
        //given
        given(memberService.saveMember(signUpRequest)).willReturn(true);
        //when & then
        mvc.perform(
                post("/signUp")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(signUpRequest))
                        .with(csrf())

        )
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.data").value(true))
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.errorCode").value(ErrorCode.OK.getStatusCode().value()))
                .andExpect(jsonPath("$.message").value(ErrorCode.OK.getMessage()));
        then(memberService).should().saveMember(signUpRequest);
    }
    
    @ParameterizedTest(name = "{index}:{1}")
    @MethodSource
    @DisplayName("[API][POST] 회원가입 테스트 - 유효성 검증 실패")
    @WithMockUser(roles = "GUEST")
    void singUpFailureTest(String email, String message) throws Exception
    {
        SignUpRequest signUpRequest = createMemberRequest(email);
        //given
        //when & then
        MvcResult mvcResult = mvc.perform(
                post("/signUp")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(signUpRequest))
                        .with(csrf())
        ).andReturn();

        String expected = Objects.requireNonNull(mvcResult.getResolvedException()).getMessage();

        assertThat(expected).contains(message);
    }

    public static Stream<Arguments> singUpFailureTest() {
        return Stream.of(
                Arguments.of(null, "이메일을 입력해주세요."),
                Arguments.of(" ", "이메일을 입력해주세요."),
                Arguments.of("email", "유효한 이메일 형식이 아닙니다.")
        );
    }

    @WithMockUser(roles = "GUEST")
    @Test
    @DisplayName("[API][POST] 회원가입 테스트 - 성공(소셜 로그인)")
    void oAuth2SingUpSuccessTest() throws Exception
    {
        SignUpOAuth2Request signUpOAuth2Request = createSignUpOAuth2Request("studentId", "nickName", "major");
        //given
        given(memberService.saveOauth2Member(signUpOAuth2Request)).willReturn(true);
        //when & then
        mvc.perform(
                        post("/signUp/oauth2")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(signUpOAuth2Request))
                                .with(csrf())

                )
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.data").value(true))
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.errorCode").value(ErrorCode.OK.getStatusCode().value()))
                .andExpect(jsonPath("$.message").value(ErrorCode.OK.getMessage()));
        then(memberService).should().saveOauth2Member(signUpOAuth2Request);
    }

    @ParameterizedTest(name = "{index}:{3}")
    @MethodSource
    @DisplayName("[API][POST] Oauth2 회원가입 테스트 - 유효성 검증 실패")
    @WithMockUser(roles = "GUEST")
    void oauth2SingUpFailureTest(String studentId, String nickName, String major, String message) throws Exception
    {
        SignUpOAuth2Request signUpOAuth2Request = createSignUpOAuth2Request(studentId, nickName, major);
        //given
        //when & then
        MvcResult mvcResult = mvc.perform(
                post("/signUp/oauth2")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(signUpOAuth2Request))
                        .with(csrf())
        ).andReturn();

        String expected = Objects.requireNonNull(mvcResult.getResolvedException()).getMessage();

        assertThat(expected).contains(message);
    }

    public static Stream<Arguments> oauth2SingUpFailureTest() {
        return Stream.of(
                Arguments.of(null,"nickName", "major", "학번을 입력해주세요."),
                Arguments.of("studentId",null, "major", "닉네임을 입력해주세요."),
                Arguments.of("studentId","nickName", null, "전공을 입력해주세요")
        );
    }

    @WithMockUser(roles = "GUEST")
    @Test
    @DisplayName("[API][POST]이메일 인증 코드 발송 테스트 - 성공")
    void sendCodeToEmailSuccessTest() throws Exception
    {
        String email = "email@naver.com";

        //given
        given(memberService.sendCodeToEmail(email))
                .willReturn(true);
        //when&then
        mvc.perform(
                post("/signUp/send/" + email)
                        .contentType(MediaType.APPLICATION_JSON)
                        .with(csrf())

        )
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.data").value(true))
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.errorCode").value(ErrorCode.OK.getStatusCode().value()))
                .andExpect(jsonPath("$.message").value(ErrorCode.OK.getMessage()));
        then(memberService).should().sendCodeToEmail(email);
    }

    @WithMockUser(roles = "GUEST")
    @Test
    @DisplayName("[API][GET] 인증 코드 일치 여부 테스트 - 성공")
    void checkConfirmCodeTest() throws Exception
    {
        ConfirmCodeRequest confirmCodeRequest = createConfirmCodeRequest();
        //given
        given(memberService.checkConfirmCode(confirmCodeRequest)).willReturn(true);
        //when & then
        mvc.perform(
                get("/signUp/check/confirmCode")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(confirmCodeRequest))
                        .with(csrf())
        )
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.data").value(true))
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.errorCode").value(ErrorCode.OK.getStatusCode().value()))
                .andExpect(jsonPath("$.message").value(ErrorCode.OK.getMessage()));
        then(memberService).should().checkConfirmCode(confirmCodeRequest);
    }
    private ConfirmCodeRequest createConfirmCodeRequest() {
        return ConfirmCodeRequest.of(
                "test@email.com",
                "123456"
        );
    }
    private static SignUpRequest createMemberRequest(String email) {
        return SignUpRequest.of(
                "name",
                email,
                "profile",
                "Abc123456*",
                "L190201201",
                "nickname",
                "male",
                "computer"
        );
    }

    private SignUpOAuth2Request createSignUpOAuth2Request(String studentId, String nickName, String major) {
        return SignUpOAuth2Request.of(
                "name",
                "email",
                "profile",
                studentId,
                nickName,
                "male",
                major);
    }


}