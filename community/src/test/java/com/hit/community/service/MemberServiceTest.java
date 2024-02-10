package com.hit.community.service;

import com.hit.community.controller.api.SignUpOAuth2Request;
import com.hit.community.custom.CustomAuthenticationProvider;
import com.hit.community.dto.*;
import com.hit.community.entity.*;
import com.hit.community.error.CustomException;
import com.hit.community.error.ErrorCode;
import com.hit.community.properties.JwtProperties;
import com.hit.community.repository.MailRepository;
import com.hit.community.repository.MemberRepository;
import com.hit.community.repository.RefreshTokenRepository;
import com.hit.community.util.JwtUtil;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Collections;
import java.util.Optional;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.*;

@ExtendWith(MockitoExtension.class)
class
MemberServiceTest {

    @Mock
    private MemberRepository memberRepository;
    @Mock
    private MailRepository mailRepository;
    @Mock
    private MailService mailService;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private JwtUtil jwtUtil;
    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @Mock
    private CustomAuthenticationProvider authenticationProvider;
    @InjectMocks
    private MemberService memberService;


    
    @Test
    @DisplayName("로그인 테스트 - 성공")
    void loginSuccessTest() throws Exception
    {

        String email = "test@naver.com";
        String password = "abc1234";
        Role role = Role.ROLE_USER;
        Authentication authenticate =  new UsernamePasswordAuthenticationToken(email, password,
                Collections.singleton(new SimpleGrantedAuthority(role.name())));
        LoginRequest loginRequest = createLoginRequest();
        TokenDto tokenDto = createTokenDto();
        //given
        given(authenticationProvider.authenticate(any())).willReturn(authenticate);
        given(jwtUtil.getToken(any(), any(),any())).willReturn(tokenDto);
        given(refreshTokenRepository.existsByRefreshToken(any())).willReturn(false);
        given(refreshTokenRepository.save(any())).willReturn(any());
        //when
        CustomTokenResponse tokenResponse = memberService.login(loginRequest);
        //then

        assertThat(tokenResponse).hasFieldOrPropertyWithValue("accessToken", tokenDto.accessToken());
        assertThat(tokenResponse).hasFieldOrPropertyWithValue("refreshToken", tokenDto.refreshToken());

        then(authenticationProvider).should().authenticate(any());
        then(jwtUtil).should().getToken(any(), any(), any());
        then(refreshTokenRepository).should().existsByRefreshToken(any());
        then(refreshTokenRepository).should().save(any());

    }



    @Test
    @DisplayName("로그인 테스트 - 실패 (이미 로그인 한 회원)")
    void loginFailureTest_AlReadyLoggedInUser() throws Exception
    {
        String email = "test@naver.com";
        String password = "abc1234";
        Role role = Role.ROLE_USER;
        Authentication authenticate =  new UsernamePasswordAuthenticationToken(email, password,
                Collections.singleton(new SimpleGrantedAuthority(role.name())));
        LoginRequest loginRequest = createLoginRequest();
        TokenDto tokenDto = createTokenDto();
        //given
        given(authenticationProvider.authenticate(any())).willReturn(authenticate);
        given(jwtUtil.getToken(any(), any(), any())).willReturn(tokenDto);
        given(refreshTokenRepository.existsByRefreshToken(any())).willReturn(true);
        //when
        CustomException exception = (CustomException) catchRuntimeException(()->memberService.login(loginRequest));
        //then

        assertThat(exception).hasMessageContaining(ErrorCode.ALREADY_LOGGED_IN_USER.getMessage());
        assertThat(exception).isInstanceOf(CustomException.class);

        then(authenticationProvider).should().authenticate(any());
        then(jwtUtil).should().getToken(any(), any(), any());
        then(refreshTokenRepository).should().existsByRefreshToken(any());
    }

    private TokenDto createTokenDto() {
        return TokenDto.of(JwtProperties.JWT_TYPE+"accessToken", "refreshToken",  "test@naver.com");
    }

    private LoginRequest createLoginRequest() {
        return LoginRequest.of("test@naver.com", "abc1234");
    }


    @Test
    @DisplayName("회원 가입 테스트 - 성공 (소셜 로그인)")
    void saveSuccessTest_OAuth2() throws Exception
    {
        Member member = createMember(LoginType.NAVER);
        SignUpOAuth2Request signUpOAuth2Request = createSignUpOAuth2Request(member);
        //given
        given(memberRepository.findByEmail(signUpOAuth2Request.email()))
                .willReturn(Optional.of(member));
        //when
        boolean isTrue = memberService.saveOauth2Member(signUpOAuth2Request);
        //then
        assertThat(isTrue).isTrue();
        then(memberRepository).should().findByEmail(signUpOAuth2Request.email());
    }



    @Test
    @DisplayName("회원 가입 테스트 - 성공 (일반 로그인)")
    void saveSuccessTest_CustomLogin() throws Exception
    {

        Member member = createMember(LoginType.GENERAL);
        SignUpRequest signUpRequest = createMemberRequest(member);
        //given
        given(passwordEncoder.encode(signUpRequest.password())).willReturn(anyString());
        //when
        boolean isTrue = memberService.saveMember(signUpRequest);
        //then
        assertThat(isTrue).isTrue();
        then(passwordEncoder).should().encode(signUpRequest.password());
        then(memberRepository).should().save(any());
    }


    @Test
    @DisplayName("회원 조회 테스트 - 성공")
    void getOAuth2MemberSuccessTest() throws Exception
    {
        String email = "email@naver.com";
        Member member = createMember(LoginType.NAVER);
        //given
        given(memberRepository.findByEmailAndType(any(), any()))
                .willReturn(Optional.of(member));
        //when
        SignUpOAuth2Response signUpOAuth2Response = memberService.getOAuth2Member(email, LoginType.NAVER);

        //then
        assertThat(signUpOAuth2Response).isNotNull();
        assertThat(signUpOAuth2Response).hasFieldOrPropertyWithValue("name",member.getName());
        assertThat(signUpOAuth2Response).hasFieldOrPropertyWithValue("email",member.getEmail());
        assertThat(signUpOAuth2Response).hasFieldOrPropertyWithValue("profile",member.getProfile());
        then(memberRepository).should().findByEmailAndType(any(), any());
    }

    @Test
    @DisplayName("회원 조회 테스트 - 실패")
    void getMemberFailureTest() throws Exception
    {
        String email = "email@naver.com";
        //given
        given(memberRepository.findByEmailAndType(any(), any()))
                .willReturn(Optional.empty());
        //when
        CustomException exception =
                (CustomException) catchRuntimeException(()->memberService.getOAuth2Member(email, LoginType.NAVER));

        //then
        assertThat(exception).hasMessageContaining(ErrorCode.USER_NOT_FOUND.getMessage());
        assertThat(exception).isInstanceOf(CustomException.class);
        then(memberRepository).should().findByEmailAndType(any(), any());
    }



    @Test
    @DisplayName("닉네임 중복 체크 테스트 - 닉네임 존재")
    void nickNameDuplicateCheckSuccessTest() throws Exception
    {
        //given
        String nickName = "nickName";
        given(memberRepository.existsByNickName(anyString())).willReturn(true);
        //when
        boolean isTrue = memberService.nickNameDuplicateCheck(nickName);

        //then
        assertThat(isTrue).isTrue();
        then(memberRepository).should().existsByNickName(anyString());
    }

    @Test
    @DisplayName("닉네임 중복 체크 테스트 - 닉네임 존재X")
    void nickNameDuplicateCheckFailureTest() throws Exception
    {
        //given
        String nickName = "nickName";
        given(memberRepository.existsByNickName(anyString())).willReturn(false);
        //when
        boolean isFalse = memberService.nickNameDuplicateCheck(nickName);

        //then
        assertThat(isFalse).isFalse();
        then(memberRepository).should().existsByNickName(anyString());
    }

    @Test
    @DisplayName("비밀번호 중복 체크 테스트 - 비밀번호 존재")
    void passwordDuplicateCheckSuccessTest() throws Exception
    {
        //given
        String password = "password";
        given(memberRepository.existsByPassword(anyString())).willReturn(true);
        //when
        boolean isTrue = memberService.passwordDuplicateCheck(password);

        //then
        assertThat(isTrue).isTrue();
        then(memberRepository).should().existsByPassword(anyString());
    }
    @Test
    @DisplayName("비밀번호 중복 체크 테스트 - 비밀번호 존재X")
    void passwordDuplicateCheckFailureTest() throws Exception
    {
        //given
        String password = "nickName";
        given(memberRepository.existsByPassword(anyString())).willReturn(false);
        //when
        boolean isFalse = memberService.passwordDuplicateCheck(password);

        //then
        assertThat(isFalse).isFalse();
        then(memberRepository).should().existsByPassword(anyString());
    }
    @Test
    @DisplayName("학번 중복 체크 테스트 - 학번 존재")
    void studentIdDuplicateCheckSuccessTest() throws Exception
    {
        //given
        String studentId = "studentId";
        given(memberRepository.existsByStudentId(anyString())).willReturn(true);
        //when
        boolean isTrue = memberService.studentIdDuplicateCheck(studentId);

        //then
        assertThat(isTrue).isTrue();
        then(memberRepository).should().existsByStudentId(anyString());
    }
    @Test
    @DisplayName("학번 중복 체크 테스트 - 학번 존재X")
    void studentIdDuplicateCheckFailureTest() throws Exception
    {
        //given
        String nickName = "nickName";
        given(memberRepository.existsByStudentId(anyString())).willReturn(false);
        //when
        boolean isFalse = memberService.studentIdDuplicateCheck(nickName);

        //then
        assertThat(isFalse).isFalse();
        then(memberRepository).should().existsByStudentId(anyString());
    }

    @Test
    @DisplayName("인증 코드 발송 테스트 - 이메일 존재 X, 처음 인증 코드 발송")
    void sendVerificationCodeIfEmailNotExistsAndConfirmCodeNotExistsTest() throws Exception
    {
        String email = "email@naver.com";
        Mail mail = createMail();

        //given
        given(memberRepository.existsByEmail(anyString())).willReturn(false);
        given(mailService.createMessage(anyString())).willReturn(mail);
        given(mailRepository.findByToEmail(anyString())).willReturn(Optional.empty());
        //when
        boolean isTrue = memberService.sendCodeToEmail(email);
        //then
        assertThat(isTrue).isTrue();
        then(memberRepository).should().existsByEmail(anyString());
        then(mailService).should().createMessage(anyString());
        then(mailRepository).should().findByToEmail(anyString());
    }
    @Test
    @DisplayName("인증 코드 발송 테스트 - 이메일 존재 X, 기존 인증 코드 존재")
    void sendVerificationCodeIfEmailNotExistsAndConfirmCodeExistsTest() throws Exception
    {
        String email = "email@naver.com";
        Mail mail = createMail();

        //given
        given(memberRepository.existsByEmail(anyString())).willReturn(false);
        given(mailService.createMessage(anyString())).willReturn(mail);
        given(mailRepository.findByToEmail(anyString())).willReturn(Optional.of(mail));
        //when
        boolean isTrue = memberService.sendCodeToEmail(email);
        //then
        assertThat(isTrue).isTrue();
        then(memberRepository).should().existsByEmail(anyString());
        then(mailService).should().createMessage(anyString());
        then(mailRepository).should().findByToEmail(anyString());
    }
    @Test
    @DisplayName("인증 코드 발송 테스트 - 기존 이메일 존재")
    void sendVerificationCodeIfEmailExistsTest() throws Exception
    {
        String email = "email@naver.com";
        //given
        given(memberRepository.existsByEmail(anyString())).willReturn(true);
        //when
        RuntimeException exception = catchRuntimeException(() -> memberService.sendCodeToEmail(email));
        //then
        assertThat(exception).isInstanceOf(CustomException.class);
        assertThat(exception).hasMessageContaining(ErrorCode.ALREADY_EXISTING_USER.getMessage());
        then(memberRepository).should().existsByEmail(anyString());
    }
    @Test
    @DisplayName("인증 코드 발송 테스트 - 인증 코드 X")
    void sendVerificationCodeIfConfirmCodeNotExistsTest() throws Exception
    {
        String email = "email@naver.com";
        Mail mail = Mail.builder()
                .confirmCode(null)
                .build();
        //given
        given(memberRepository.existsByEmail(anyString())).willReturn(false);
        given(mailService.createMessage(anyString())).willReturn(mail);
        //when
        RuntimeException exception = catchRuntimeException(() -> memberService.sendCodeToEmail(email));
        //then
        assertThat(exception).isInstanceOf(CustomException.class);
        assertThat(exception).hasMessageContaining(ErrorCode.CONFIRM_CODE_NOT_EXISTS.getMessage());
        then(memberRepository).should().existsByEmail(anyString());
    }
    @Test
    @DisplayName("인증 코드 체크 테스트 - 성공")
    void checkConfirmCodeSuccessTest() throws Exception
    {
        Mail mail = createMail();
        ConfirmCodeRequest confirmCodeRequest = createConfirmCodeRequest();
        //given
        given(mailRepository.findByToEmail(anyString())).willReturn(Optional.of(mail));
        //when
        boolean isTrue = memberService.checkConfirmCode(confirmCodeRequest);

        //then
        assertThat(isTrue).isTrue();
        then(mailRepository).should().findByToEmail(anyString());
    }

    @Test
    @DisplayName("인증 코드 체크 테스트 - 실패(Mail 존재 X)")
    void checkConfirmCodeFailure_No_Mail_Test() throws Exception
    {
        ConfirmCodeRequest confirmCodeRequest = createConfirmCodeRequest();
        //given
        given(mailRepository.findByToEmail(anyString())).willReturn(Optional.empty());
        //when
        RuntimeException exception =
                catchRuntimeException(()->memberService.checkConfirmCode(confirmCodeRequest));

        //then
        assertThat(exception).isInstanceOf(CustomException.class);
        assertThat(exception).hasMessageContaining(ErrorCode.CONFIRM_CODE_MISMATCH.getMessage());
        then(mailRepository).should().findByToEmail(anyString());
    }

    @Test
    @DisplayName("인증 코드 체크 테스트 - 실패(confirm code 존재 X)")
    void checkConfirmCodeFailure_No_ConfirmCode_Test() throws Exception
    {
        ConfirmCodeRequest confirmCodeRequest = createConfirmCodeRequest();
        Mail mail = Mail.builder().confirmCode(null).build();
        //given
        given(mailRepository.findByToEmail(anyString())).willReturn(Optional.of(mail));
        //when
        RuntimeException exception =
                catchRuntimeException(()->memberService.checkConfirmCode(confirmCodeRequest));

        //then
        assertThat(exception).isInstanceOf(CustomException.class);
        assertThat(exception).hasMessageContaining(ErrorCode.CONFIRM_CODE_NOT_EXISTS.getMessage());
        then(mailRepository).should().findByToEmail(anyString());
    }
    @Test
    @DisplayName("인증 코드 체크 테스트 - 실패(confirm code 불일치)")
    void checkConfirmCodeFailure_mismatch_Test() throws Exception
    {
        ConfirmCodeRequest confirmCodeRequest = createConfirmCodeRequest();
        Mail mail = Mail.builder()
                .toEmail(confirmCodeRequest.email())
                .confirmCode("456789")
                .build();
        //given
        given(mailRepository.findByToEmail(anyString())).willReturn(Optional.of(mail));
        //when
        RuntimeException exception =
                catchRuntimeException(()->memberService.checkConfirmCode(confirmCodeRequest));

        //then
        assertThat(exception).isInstanceOf(CustomException.class);
        assertThat(exception).hasMessageContaining(ErrorCode.CONFIRM_CODE_MISMATCH.getMessage());
        then(mailRepository).should().findByToEmail(anyString());
    }

    private Mail createMail() {
        return Mail.builder()
                .toEmail("test@email.com")
                .confirmCode("123456")
                .build();
    }
    @Test
    @DisplayName("refresh_token 재발급 테스트 - 성공")
    void reissueSuccessTest() throws Exception
    {
        String email = "test@naver.com";
        String refreshToken = "refreshToken";

        TokenDto tokenDto = TokenDto.of("accessToken", refreshToken, email);
        //given
        given(jwtUtil.validateToken(refreshToken)).willReturn(true);
        given(refreshTokenRepository.existsByRefreshToken(any())).willReturn(true);
        given(jwtUtil.getEmail(any())).willReturn(email);
        given(jwtUtil.getLoginType(any())).willReturn(LoginType.GENERAL);
        given(jwtUtil.getToken(any(), any(), any())).willReturn(tokenDto);
        //when
        String accessToken = memberService.reissue(refreshToken);

        //then
        assertThat(accessToken).isNotEmpty();
        assertThat(accessToken).isEqualTo("accessToken");


        then(jwtUtil).should().validateToken(refreshToken);
        then(refreshTokenRepository).should().existsByRefreshToken(any());
        then(jwtUtil).should().getEmail(any());
        then(jwtUtil).should().getLoginType(any());
        then(jwtUtil).should().getToken(any(), any(), any());
    }

    @Test
    @DisplayName("refresh_token 재발급 테스트 - 실패 (refreshToken Null)")
    void reissueFailureTest_RefreshTokenIsNull() throws Exception
    {
        //given
        //when
        CustomException exception = (CustomException) catchRuntimeException(()->memberService.reissue(null));

        //then
        assertThat(exception).isInstanceOf(CustomException.class);
        assertThat(exception).hasMessageContaining(ErrorCode.NOT_EXIST_TOKEN.getMessage());

    }

    @Test
    @DisplayName("refresh_token 재발급 테스트 - 실패 (validate 실패)")
    void reissueFailureTest_ValidateFailed() throws Exception
    {

        String refreshToken = "refreshToken";
        //given
        given(jwtUtil.validateToken(refreshToken)).willThrow(CustomException.class);
        //when
        CustomException exception = (CustomException) catchRuntimeException(()->memberService.reissue(refreshToken));

        //then
        assertThat(exception).isInstanceOf(CustomException.class);

        then(jwtUtil).should().validateToken(refreshToken);
    }

    @Test
    @DisplayName("refresh_token 재발급 테스트 - 실패 (회원 정보 존재 X)")
    void reissueFailureTest_NotExistRefreshToken() throws Exception
    {

        String refreshToken = "refreshToken";

        //given
        given(jwtUtil.validateToken(any())).willReturn(true);
        given(refreshTokenRepository.existsByRefreshToken(any())).willReturn(false);
        //when
        CustomException exception = (CustomException) catchRuntimeException(()->memberService.reissue(refreshToken));

        //then
        assertThat(exception).isInstanceOf(CustomException.class);
        assertThat(exception).hasMessageContaining(ErrorCode.NOT_EXIST_TOKEN.getMessage());

        then(jwtUtil).should().validateToken(any());
        then(refreshTokenRepository).should().existsByRefreshToken(any());
    }



    @Test
    @DisplayName("로그아웃 테스트 - 성공")
    void logoutSuccessTest() throws Exception
    {

        Cookie cookie = new Cookie(JwtProperties.REFRESH_TOKEN_NAME, "testRefreshToken");
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(JwtProperties.AUTHORIZATION, JwtProperties.JWT_TYPE+"testAccessToken");
        request.setCookies(cookie);
        RefreshToken refreshToken = createRefreshToken();
        //given
        given(jwtUtil.validateToken(any())).willReturn(true);
        willDoNothing().given(refreshTokenRepository).delete(any());
        given(refreshTokenRepository.findByRefreshToken(any())).willReturn(Optional.of(refreshToken));
        willDoNothing().given(jwtUtil).addBlackList(any());

        //when
        boolean isTrue = memberService.logout(request);

        //then
        assertThat(isTrue).isTrue();

        then(jwtUtil).should().validateToken(any());
        then(refreshTokenRepository).should().delete(any());
        then(refreshTokenRepository).should().findByRefreshToken(any());
        then(jwtUtil).should().addBlackList(any());
    }



    @Test
    @DisplayName("로그아웃 테스트 - 실패 (Refresh Token Cookie Null 값)")
    void logoutFailureTest_CookieEmpty() throws Exception
    {

        Cookie cookie = new Cookie(JwtProperties.REFRESH_TOKEN_NAME, null);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(JwtProperties.AUTHORIZATION, JwtProperties.JWT_TYPE+"testAccessToken");
        request.setCookies(cookie);
        //given
        //when
        CustomException exception = (CustomException)catchRuntimeException(()->memberService.logout(request));

        //then
        assertThat(exception).isInstanceOf(CustomException.class);
        assertThat(exception).hasMessage(ErrorCode.NOT_EXIST_TOKEN.getMessage());

    }


    @DisplayName("로그아웃 테스트 - 실패 (email Null and accessToken Not Bearer)")
    @MethodSource
    @ParameterizedTest(name = "{0} - {1}")
    void logoutFailureTest_emailAndAccessTokenEmpty(String email, String accessToken) throws Exception
    {

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(JwtProperties.AUTHORIZATION, accessToken);
        //given
        //when
        CustomException exception = (CustomException) catchRuntimeException(()->memberService.logout(request));

        //then
        assertThat(exception).isInstanceOf(CustomException.class);
        assertThat(exception).hasMessageContaining(ErrorCode.NOT_EXIST_TOKEN.getMessage());

    }

    static Stream<Arguments> logoutFailureTest_emailAndAccessTokenEmpty(){
        String email = "test@email.com";
        return Stream.of(
                Arguments.of(email, "accessToken"),
                Arguments.of(null, "Bearer accessToken"),
                Arguments.of(null, "accessToken")
        );
    }



    @Test
    @DisplayName("로그아웃 테스트 - 실패(올바르지 않은 토큰 정보)")
    void logoutFailureTest_InvalidToken() throws Exception
    {

        Cookie cookie = new Cookie(JwtProperties.REFRESH_TOKEN_NAME, "testRefreshToken");
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(JwtProperties.AUTHORIZATION, JwtProperties.JWT_TYPE+"testAccessToken");
        request.setCookies(cookie);
        //given
        given(jwtUtil.validateToken(any())).willReturn(false);

        //when
        CustomException exception = (CustomException) catchRuntimeException(()->memberService.logout(request));

        //then
        assertThat(exception).isInstanceOf(CustomException.class);
        assertThat(exception).hasMessageContaining(ErrorCode.INVALID_TOKEN.getMessage());

        then(jwtUtil).should().validateToken(any());
    }

    @Test
    @DisplayName("로그아웃 테스트 - 실패(refreshToken 불일치)")
    void logoutFailureTest_RefreshTokenMisMatch() throws Exception
    {

        Cookie cookie = new Cookie(JwtProperties.REFRESH_TOKEN_NAME, "testMisMatchRefreshToken");
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(JwtProperties.AUTHORIZATION, JwtProperties.JWT_TYPE+"testAccessToken");
        request.setCookies(cookie);
        RefreshToken refreshToken = createRefreshToken();
        //given
        given(jwtUtil.validateToken(any())).willReturn(true);
        given(refreshTokenRepository.findByRefreshToken(any())).willReturn(Optional.of(refreshToken));

        //when
        CustomException exception = (CustomException) catchRuntimeException(()->memberService.logout(request));

        //then
        assertThat(exception).isInstanceOf(CustomException.class);
        assertThat(exception).hasMessageContaining(ErrorCode.ALREADY_LOGGED_OUT_USER.getMessage());

        then(jwtUtil).should().validateToken(any());
        then(refreshTokenRepository).should().findByRefreshToken(any());

    }

    private RefreshToken createRefreshToken() {
        return RefreshToken.builder()
                .refreshToken("testRefreshToken")
                .email("test@eamail.com")
                .build();
    }

    @Test
    @DisplayName("이메일 찾기 테스트 - 성공")
    void findEmailSuccessTest() throws Exception
    {

        Member member = createMember(LoginType.GENERAL);
        FindEmailRequest findEmailRequest = createFindEmailRequest();
        //given
        given(memberRepository.findByNameAndStudentIdAndType(any(), any(), any()))
                .willReturn(Optional.of(member));
        //when
        String email = memberService.findEmail(findEmailRequest);
        //then
        assertThat(email).isEqualTo(member.getEmail());

        then(memberRepository).should().findByNameAndStudentIdAndType(any(), any(), any());
    }

    @Test
    @DisplayName("이메일 찾기 테스트 - 실패 (이름 또는 학번 존재 X)")
    void findEmailFailureTest_NotExistNameOrStudentId() throws Exception
    {
        FindEmailRequest findEmailRequest = createFindEmailRequest();
        //given
        given(memberRepository.findByNameAndStudentIdAndType(any(), any(), any()))
                .willReturn(Optional.empty());
        //when
       CustomException exception =
               (CustomException) catchRuntimeException(()->memberService.findEmail(findEmailRequest));
        //then
        assertThat(exception).isInstanceOf(CustomException.class);
        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.USER_NOT_FOUND);
        assertThat(exception.getMessage()).isEqualTo(ErrorCode.USER_NOT_FOUND.getMessage());

        then(memberRepository).should().findByNameAndStudentIdAndType(any(), any(), any());
    }

    @Test
    @DisplayName("회원 유무 테스트 - 성공 (비밀번호 찾기)")
    void checkMemberSuccessTest() throws Exception
    {
        CheckMemberRequest checkMemberRequest = createCheckMemberReqeust();
        //given
        given(memberRepository.existsByNameAndEmailAndType(any(), any(), any()))
                .willReturn(true);
        //when
        boolean isTrue = memberService.checkMember(checkMemberRequest);
        //then
        assertThat(isTrue).isTrue();

        then(memberRepository).should().existsByNameAndEmailAndType(any(), any(), any());
    }

    @Test
    @DisplayName("회원 유무 테스트 - 실패 (회원 존재 X, 비밀번호 찾기)")
    void checkMemberFailureTest_NotExistMember() throws Exception
    {
        CheckMemberRequest checkMemberRequest = createCheckMemberReqeust();
        //given
        given(memberRepository.existsByNameAndEmailAndType(any(), any(), any()))
                .willReturn(false);
        //when
        CustomException exception =
                (CustomException) catchRuntimeException(()->memberService.checkMember(checkMemberRequest));
        //then
        assertThat(exception).isInstanceOf(CustomException.class);
        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.USER_NOT_FOUND);
        assertThat(exception.getMessage()).isEqualTo(ErrorCode.USER_NOT_FOUND.getMessage());

        then(memberRepository).should().existsByNameAndEmailAndType(any(), any(), any());
    }
    
    @Test
    @DisplayName("새 비밀번호 변경 테스트 - 성공")
    void changePasswordSuccessTest() throws Exception
    {
        Member member = createMember(LoginType.GENERAL);
        ChangePasswordRequest changePasswordRequest = createChangePasswordRequest();
        //given
        given(memberRepository.findByEmail(any())).willReturn(Optional.of(member));
        //when
        boolean isTrue = memberService.changePassword(changePasswordRequest);
        //then
        assertThat(isTrue).isTrue();

        then(memberRepository).should().findByEmail(any());
    }

    @Test
    @DisplayName("새 비밀번호 변경 테스트 - 실패 (회원 존재 X)")
    void changePasswordFailureTest_NotExistMember() throws Exception
    {

        ChangePasswordRequest changePasswordRequest = createChangePasswordRequest();
        //given
        given(memberRepository.findByEmail(any())).willReturn(Optional.empty());
        //when
        CustomException exception =
                (CustomException) catchRuntimeException(()->memberService.changePassword(changePasswordRequest));
        //then
        assertThat(exception).isInstanceOf(CustomException.class);
        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.USER_NOT_FOUND);
        assertThat(exception.getMessage()).isEqualTo(ErrorCode.USER_NOT_FOUND.getMessage());

        then(memberRepository).should().findByEmail(any());
    }

    @Test
    @DisplayName("회원탈퇴 성공 테스트")
    void withdrawalSuccessTest() throws Exception
    {
        String email = "test@naver.com";
        String refreshToken = "refreshToken";
        RefreshToken refreshTokenEntity = RefreshToken.builder()
                .email(email)
                .refreshToken(refreshToken)
                .build();
        Member member = createMember(LoginType.GENERAL);
        //given
        given(jwtUtil.validateToken(refreshToken)).willReturn(true);
        given(refreshTokenRepository.findByRefreshToken(any())).willReturn(Optional.of(refreshTokenEntity));
        given(jwtUtil.getEmail(any())).willReturn(email);
        given(jwtUtil.getLoginType(any())).willReturn(LoginType.GENERAL);
        given(memberRepository.findByEmailAndType(any(), any())).willReturn(Optional.of(member));
        //when
        boolean isTrue = memberService.withdrawal(refreshToken);

        //then
        assertThat(isTrue).isTrue();

        then(jwtUtil).should().validateToken(refreshToken);
        then(refreshTokenRepository).should().findByRefreshToken(any());
        then(jwtUtil).should().getEmail(any());
        then(jwtUtil).should().getLoginType(any());
        then(memberRepository).should().findByEmailAndType(any(), any());
        then(refreshTokenRepository).should().delete(any());
        then(memberRepository).should().delete(any());

    }
    @Test
    @DisplayName("회원탈퇴 테스트 - 실패 (refreshToken Null)")
    void withdrawalFailureTest_RefreshTokenIsNull() throws Exception
    {
        //given
        //when
        CustomException exception = (CustomException) catchRuntimeException(()->memberService.withdrawal(null));

        //then
        assertThat(exception).isInstanceOf(CustomException.class);
        assertThat(exception).hasMessageContaining(ErrorCode.NOT_EXIST_TOKEN.getMessage());

    }

    @Test
    @DisplayName("회원탈퇴 테스트 - 실패 (validate 실패)")
    void withdrawalFailureTest_ValidateFailed() throws Exception
    {

        String refreshToken = "refreshToken";
        //given
        given(jwtUtil.validateToken(refreshToken)).willThrow(CustomException.class);
        //when
        CustomException exception = (CustomException) catchRuntimeException(()->memberService.withdrawal(refreshToken));

        //then
        assertThat(exception).isInstanceOf(CustomException.class);

        then(jwtUtil).should().validateToken(refreshToken);
    }

    @Test
    @DisplayName("회원탈퇴 테스트 - 실패 (refreshTokenEntity 존재 X)")
    void withdrawalFailureTest_NotExistRefreshToken() throws Exception
    {

        String refreshToken = "refreshToken";

        //given
        given(jwtUtil.validateToken(any())).willReturn(true);
        given(refreshTokenRepository.findByRefreshToken(any())).willReturn(Optional.empty());
        //when
        CustomException exception = (CustomException) catchRuntimeException(()->memberService.withdrawal(refreshToken));

        //then
        assertThat(exception).isInstanceOf(CustomException.class);
        assertThat(exception).hasMessageContaining(ErrorCode.NOT_EXIST_TOKEN.getMessage());

        then(jwtUtil).should().validateToken(any());
        then(refreshTokenRepository).should().findByRefreshToken(any());
    }


    @Test
    @DisplayName("회원탈퇴 테스트 - 실패 (회원 정보 존재 X)")
    void withdrawalFailureTest_NotExistMember() throws Exception
    {
        String email = "test@naver.com";
        String refreshToken = "refreshToken";
        RefreshToken refreshTokenEntity = RefreshToken.builder()
                .email(email)
                .refreshToken(refreshToken)
                .build();

        //given
        given(jwtUtil.validateToken(any())).willReturn(true);
        given(refreshTokenRepository.findByRefreshToken(any())).willReturn(Optional.of(refreshTokenEntity));
        given(memberRepository.findByEmailAndType(any(), any())).willReturn(Optional.empty());
        //when
        CustomException exception = (CustomException) catchRuntimeException(()->memberService.withdrawal(refreshToken));

        //then
        assertThat(exception).isInstanceOf(CustomException.class);
        assertThat(exception).hasMessageContaining(ErrorCode.USER_NOT_FOUND.getMessage());

        then(jwtUtil).should().validateToken(any());
        then(refreshTokenRepository).should().findByRefreshToken(any());
        then(memberRepository).should().findByEmailAndType(any(), any());
    }

    private ConfirmCodeRequest createConfirmCodeRequest() {
        return ConfirmCodeRequest.of(
                "test@email.com",
                "123456"
        );
    }
    private ChangePasswordRequest createChangePasswordRequest() {
        return ChangePasswordRequest.of("test@email.com", "Abc123456*");
    }

    private CheckMemberRequest createCheckMemberReqeust() {
        return CheckMemberRequest.of("name", "test@email.com");
    }

    private FindEmailRequest createFindEmailRequest() {
        return FindEmailRequest.of("name", "L190201201");
    }

    private SignUpRequest createMemberRequest(Member member) {
        return SignUpRequest.of(
                member.getEmail(),
                member.getName(),
                member.getProfile(),
                "Yun970804*",
                "L190201201",
                "nickName",
                "male",
                "computer"
        );
    }
    private SignUpOAuth2Request createSignUpOAuth2Request(Member member) {
        return SignUpOAuth2Request.of(
                member.getEmail(),
                member.getName(),
                member.getProfile(),
                "L190201201",
                "nickName",
                "male",
                "computer");
    }

    private Member createMember(LoginType type) {
        return Member.builder()
                .email("email@naver.com")
                .name("name")
                .profile("profile")
                .role(Role.ROLE_ADMIN)
                .type(type)
                .build();
    }

}