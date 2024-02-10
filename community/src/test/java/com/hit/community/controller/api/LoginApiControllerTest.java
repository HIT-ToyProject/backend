package com.hit.community.controller.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.hit.community.dto.*;
import com.hit.community.error.ErrorCode;
import com.hit.community.properties.JwtProperties;
import com.hit.community.service.MemberService;
import jakarta.servlet.http.Cookie;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validator;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Collections;
import java.util.Set;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(controllers = LoginApiController.class)
class LoginApiControllerTest {

    @MockBean
    private MemberService memberService;
    @Autowired
    private ObjectMapper objectMapper;
    @Autowired
    private Validator validator;

    @Autowired
    private MockMvc mvc;


    @WithMockUser(roles = "GUEST")
    @Test
    @DisplayName("[API][POST] 로그인 성공 테스트")
    void loginSuccessTest() throws Exception
    {

        LoginRequest loginRequest = createLoginRequest("test@email.com", "abc1234");
        CustomTokenResponse tokenResponse = createTokenResponse("refreshToken");
        //given
        given(memberService.login(any())).willReturn(tokenResponse);
        //when&then
        mvc.perform(post("/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest))
                .with(csrf())
        )
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.data.email").value(loginRequest.email()))
                .andExpect(jsonPath("$.data.accessToken").value(tokenResponse.accessToken()))
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.errorCode").value(ErrorCode.OK.getStatusCode().value()))
                .andExpect(jsonPath("$.message").value(ErrorCode.OK.getMessage()));

        then(memberService).should().login(any());
    }
    
    @WithMockUser(roles = "GUEST")
    @MethodSource
    @ParameterizedTest(name = "{index} - {0}, {1}")
    @DisplayName("[API][POST] 로그인 실패 테스트 - LoginRequest 검증 실패")
    void loginFailureTest_Verification_Failed(String email, String password, String message) throws Exception
    {

        LoginRequest loginRequest = createLoginRequest(email, password);
        //given

        //when&then
        Set<ConstraintViolation<LoginRequest>> validate = validator.validate(loginRequest);

        assertThat(validate).isNotEmpty();
        validate.forEach(value->{
            assertThat(value.getMessage()).isEqualTo(message);
        });

    }

    static Stream<Arguments> loginFailureTest_Verification_Failed(){
        return Stream.of(
                Arguments.of(null, "abc1234", "이메일 또는 비밀번호를 입력해주세요."),
                Arguments.of("test@naver.com",null ,"이메일 또는 비밀번호를 입력해주세요."),
                Arguments.of(null,null,"이메일 또는 비밀번호를 입력해주세요.")
        );
    }

    private LoginRequest createLoginRequest(String email, String password) {
        return LoginRequest.of(email, password);
    }


    @WithMockUser(roles = "USER")
    @Test
    @DisplayName("[API][POST]Refresh Token 재발급 테스트 - 성공")
    void reissueSuccessTest() throws Exception
    {
        String email = "test@eamail.com";
        String password = "abc1234";
        String role = "USER";
        String refreshToken = "refreshToken";
        CustomTokenResponse tokenResponse = createTokenResponse(refreshToken);
        Cookie cookie = new Cookie(JwtProperties.REFRESH_TOKEN_NAME, refreshToken);
        Authentication authentication = new UsernamePasswordAuthenticationToken(email, password,
                Collections.singleton(new SimpleGrantedAuthority(role)));
        //given
        given(memberService.reissue(refreshToken))
                .willReturn(tokenResponse.accessToken());

        //when & then
        mvc.perform(
                post("/login/reissue")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer accessToken")
                        .cookie(cookie)
                        .contentType(MediaType.APPLICATION_JSON)
                        .with(authentication(authentication))
                        .with(csrf())
                )
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON_VALUE))
                .andExpect(jsonPath("$.data").value(true))
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.errorCode").value(ErrorCode.OK.getStatusCode().value()))
                .andExpect(jsonPath("$.message").value(ErrorCode.OK.getMessage()));
        then(memberService).should().reissue(refreshToken);
    }

    @WithMockUser(roles = "GUEST")
    @Test
    @DisplayName("[API][GET] 이메일 찾기 테스트 - 성공")
    void findEmailSuccessTest() throws Exception
    {
        String email = "email";
        FindEmailRequest findEmailRequest = createFindEmailRequest("name", "L190201201");
        //given
        given(memberService.findEmail(any())).willReturn(email);

        //when & then
        mvc.perform(get("/login/findEmail")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(findEmailRequest))
                .with(csrf())
        ).andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.data").value(email))
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.errorCode").value(ErrorCode.OK.getStatusCode().value()))
                .andExpect(jsonPath("$.message").value(ErrorCode.OK.getMessage()));

        then(memberService).should().findEmail(any());

    }
    
    @ParameterizedTest(name = "{0} - {1} : {2}")
    @MethodSource
    @DisplayName("이메일 찾기 검증 테스트")
    void findEmailValidationTest(String name, String studentId) throws Exception
    {

        //given
        FindEmailRequest findEmailRequest = createFindEmailRequest(name, studentId);
        //when
        Set<ConstraintViolation<FindEmailRequest>> validate = validator.validate(findEmailRequest);
        //then
        assertThat(validate).isNotEmpty();
        validate.forEach(v->assertThat(v.getMessage()).isEqualTo("이름과 학번은 공백일 수 없습니다."));
    }
    static Stream<Arguments> findEmailValidationTest(){
        return Stream.of(
                Arguments.of("name", null),
                Arguments.of(null, "studentId"),
                Arguments.of(null, null)
        );
    }


    @WithMockUser(roles = "GUEST")
    @Test
    @DisplayName("[API][GET] 회원 존재 유무 테스트")
    void checkMemberSuccessTest() throws Exception
    {
        CheckMemberRequest checkMemberRequest = createCheckMemberRequest("name", "test@email.com");
        //given
        given(memberService.checkMember(any())).willReturn(true);
        //when & then
        mvc.perform(get("/login/checkMember")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(checkMemberRequest))
                .with(csrf())
        ).andExpect(status().isOk())
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.data").value(true))
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.errorCode").value(ErrorCode.OK.getStatusCode().value()))
                .andExpect(jsonPath("$.message").value(ErrorCode.OK.getMessage()));

        then(memberService).should().checkMember(any());
    }

    @ParameterizedTest(name = "{0} - {1} : {2}")
    @MethodSource
    @DisplayName("회원 존재 유무 검증 테스트")
    void checkMemberValidationTest(String name, String email) throws Exception
    {

        //given
        CheckMemberRequest checkMemberRequest = createCheckMemberRequest(name, email);
        //when
        Set<ConstraintViolation<CheckMemberRequest>> validate = validator.validate(checkMemberRequest);
        //then
        assertThat(validate).isNotEmpty();
        validate.forEach(v->assertThat(v.getMessage()).isEqualTo("이름과 이메일은 공백일 수 없습니다."));
    }
    static Stream<Arguments> checkMemberValidationTest(){
        return Stream.of(
                Arguments.of("name", null),
                Arguments.of(null, "test@email.com"),
                Arguments.of(null, null)
        );
    }

    @WithMockUser(roles = "GUEST")
    @Test
    @DisplayName("[API][POST] 비밀번호 변경 테스트 - 성공")
    void changePasswordSuccessTest() throws Exception
    {
        ChangePasswordRequest changePasswordRequest = createChangePasswordRequest("name", "Abc123456*");
        //given
        given(memberService.changePassword(any())).willReturn(true);
        //when & then
        mvc.perform(post("/login/changePassword")
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(objectMapper.writeValueAsString(changePasswordRequest))
                .with(csrf())
        ).andExpect(status().isOk())
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.data").value(true))
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.errorCode").value(ErrorCode.OK.getStatusCode().value()))
                .andExpect(jsonPath("$.message").value(ErrorCode.OK.getMessage()));

        then(memberService).should().changePassword(any());
    }

    @ParameterizedTest(name = "{0} : {1}")
    @MethodSource
    @DisplayName("회원 존재 유무 검증 테스트")
    void changePasswordValidationTest(String password, String message) throws Exception
    {

        //given
        ChangePasswordRequest changePasswordRequest = createChangePasswordRequest("name", password);
        //when
        Set<ConstraintViolation<ChangePasswordRequest>> validate = validator.validate(changePasswordRequest);
        //then
        assertThat(validate).isNotEmpty();
        validate.forEach(v->assertThat(v.getMessage()).isEqualTo(message));
    }
    static Stream<Arguments> changePasswordValidationTest(){
        return Stream.of(
                Arguments.of(null, "비밀번호를 입력해 주세요."),
                Arguments.of("abs12345", "비밀번호는 8~16자 영문 대 소문자, 숫자, 특수문자를 사용해 주세요."),
                Arguments.of("123456*", "비밀번호는 8~16자 영문 대 소문자, 숫자, 특수문자를 사용해 주세요."),
                Arguments.of("abs123456", "비밀번호는 8~16자 영문 대 소문자, 숫자, 특수문자를 사용해 주세요."),
                Arguments.of("abs123*", "비밀번호는 8~16자 영문 대 소문자, 숫자, 특수문자를 사용해 주세요.")
        );
    }

    @WithMockUser(roles = "USER")
    @Test
    @DisplayName("[API][POST]회원탈퇴 테스트 - 성공")
    void withdrawalSuccessTest() throws Exception
    {
        String email = "test@eamail.com";
        String password = "abc1234";
        String role = "USER";
        String refreshToken = "refreshToken";
        Cookie cookie = new Cookie(JwtProperties.REFRESH_TOKEN_NAME, refreshToken);
        Authentication authentication = new UsernamePasswordAuthenticationToken(email, password,
                Collections.singleton(new SimpleGrantedAuthority(role)));
        //given
        given(memberService.withdrawal(refreshToken))
                .willReturn(true);

        //when & then
        mvc.perform(
                        post("/login/withdrawal")
                                .cookie(cookie)
                                .contentType(MediaType.APPLICATION_JSON)
                                .with(authentication(authentication))
                                .with(csrf())
                )
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON_VALUE))
                .andExpect(jsonPath("$.data").value(true))
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.errorCode").value(ErrorCode.OK.getStatusCode().value()))
                .andExpect(jsonPath("$.message").value(ErrorCode.OK.getMessage()));
        then(memberService).should().withdrawal(refreshToken);
    }

    private ChangePasswordRequest createChangePasswordRequest(String name, String password) {
        return ChangePasswordRequest.of(name, password);
    }
    private CheckMemberRequest createCheckMemberRequest(String name, String email) {
        return CheckMemberRequest.of(name, email);
    }


    private FindEmailRequest createFindEmailRequest(String name, String studentId) {
        return FindEmailRequest.of(name, studentId);
    }

    private CustomTokenResponse createTokenResponse(String refreshToken) {
        return CustomTokenResponse.of("accessToken", refreshToken);

    }

}