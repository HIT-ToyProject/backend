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
import com.hit.community.util.CookieUtil;
import com.hit.community.util.JwtUtil;
import io.jsonwebtoken.lang.Strings;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;


@RequiredArgsConstructor
@Transactional(readOnly = true)
@Service
public class MemberService {

    private final MemberRepository memberRepository;
    private final MailService mailService;
    private final MailRepository mailRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final RefreshTokenRepository refreshTokenRepository;
    private final CustomAuthenticationProvider authenticationProvider;


    @Transactional
    public CustomTokenResponse login(LoginRequest loginRequest) {
        Authentication authentication =
                new UsernamePasswordAuthenticationToken(loginRequest.email(), loginRequest.password());
        Authentication authenticate = authenticationProvider.authenticate(authentication);
        SecurityContextHolder.getContext().setAuthentication(authenticate);

        String email = (String) authenticate.getPrincipal();
        String roleName = authenticate.getAuthorities().stream().map(GrantedAuthority::getAuthority).findFirst()
                .orElseThrow(() -> new CustomException(ErrorCode.NOT_EXIST_AUTHORIZATION));
        Role role = Role.checkRole(roleName);

        TokenDto tokenDto = createToken(email, role);

        return CustomTokenResponse.fromResponse(tokenDto);
    }

    private TokenDto createToken(String email, Role role) {
        TokenDto tokenDto = jwtUtil.getToken(email, role, LoginType.GENERAL);
        saveRefreshToken(tokenDto);
        return tokenDto;
    }

    private void saveRefreshToken(TokenDto tokenDto) {
        boolean isLoginUser = refreshTokenRepository.existsByRefreshToken(tokenDto.refreshToken());
        if (isLoginUser) {
            throw new CustomException(ErrorCode.ALREADY_LOGGED_IN_USER);
        } else {
            RefreshToken refreshToken = tokenDto.toRefreshTokenEntity();
            refreshTokenRepository.save(refreshToken);
        }
    }

    public SignUpOAuth2Response getOAuth2Member(String email, LoginType type) {
        return memberRepository.findByEmailAndType(email, type).map(SignUpOAuth2Response::fromMemberResponse)
                .orElseThrow(() -> new CustomException(ErrorCode.USER_NOT_FOUND));
    }

    @Transactional
    public boolean saveMember(SignUpRequest signUpRequest) {
        String passwordEncode = passwordEncoder.encode(signUpRequest.password());
        memberRepository.save(signUpRequest.toEntity(passwordEncode, LoginType.GENERAL));
        return true;
    }

    @Transactional
    public Boolean saveOauth2Member(SignUpOAuth2Request signUpOAuth2Request) {
        memberRepository.findByEmail(signUpOAuth2Request.email())
                .map(data -> data.toEntity(signUpOAuth2Request))
                .orElseThrow(()->new CustomException(ErrorCode.INTERNAL_SERVER));
        return true;
    }

    @Transactional
    public boolean sendCodeToEmail(String email) {
        emailDuplicateCheck(email);
        Mail createdMail = mailService.createMessage(email);
        if (!Strings.hasText(createdMail.getConfirmCode())) {
            throw new CustomException(ErrorCode.CONFIRM_CODE_NOT_EXISTS);
        }
        mailRepository.findByToEmail(email)
                .map(data -> {
                    mailRepository.delete(data);
                    return mailRepository.save(createdMail);
                }).orElse(mailRepository.save(createdMail));
        return true;
    }


    public boolean checkConfirmCode(ConfirmCodeRequest confirmCodeRequest) {
        Mail mail = mailRepository.findByToEmail(confirmCodeRequest.email())
                .orElseThrow(() -> new CustomException(ErrorCode.CONFIRM_CODE_MISMATCH));
        if (!Strings.hasText(mail.getConfirmCode())) {
            throw new CustomException(ErrorCode.CONFIRM_CODE_NOT_EXISTS);
        }
        if (!confirmCodeRequest.confirmCode().equals(mail.getConfirmCode())) {
            throw new CustomException(ErrorCode.CONFIRM_CODE_MISMATCH);
        }

        return true;
    }

    public void emailDuplicateCheck(String email) {
        boolean existByEmail = memberRepository.existsByEmail(email);
        if (existByEmail) {
            throw new CustomException(ErrorCode.ALREADY_EXISTING_USER);
        }
    }

    public boolean nickNameDuplicateCheck(String nickName) {
        return memberRepository.existsByNickName(nickName);
    }

    public boolean passwordDuplicateCheck(String password) {
        return memberRepository.existsByPassword(password);
    }

    public boolean studentIdDuplicateCheck(String studentId) {
        return memberRepository.existsByStudentId(studentId);
    }

    @Transactional
    public String reissue(String refreshToken) {
        if (!Strings.hasText(refreshToken)) {
            throw new CustomException(ErrorCode.NOT_EXIST_TOKEN);
        }
        if (!jwtUtil.validateToken(refreshToken)) {
            throw new CustomException(ErrorCode.INVALID_TOKEN);
        }

        if(!refreshTokenRepository.existsByRefreshToken(refreshToken)){
            throw new CustomException(ErrorCode.NOT_EXIST_TOKEN);
        }

        String email = jwtUtil.getEmail(refreshToken);
        LoginType type = jwtUtil.getLoginType(refreshToken);
        TokenDto token = jwtUtil.getToken(email, Role.ROLE_USER, type);
        return token.accessToken();
    }

    @Transactional
    public boolean logout(HttpServletRequest request){

        String accessToken = resolveToken(request.getHeader(HttpHeaders.AUTHORIZATION));
        if (!Strings.hasText(accessToken)) {
            throw new CustomException(ErrorCode.NOT_EXIST_TOKEN);
        }

        String refreshToken = CookieUtil.getCookie(request, JwtProperties.REFRESH_TOKEN_NAME)
                .map(Cookie::getValue)
                .orElseThrow(()->new CustomException(ErrorCode.NOT_EXIST_TOKEN));

        if (!jwtUtil.validateToken(accessToken)) {
            throw new CustomException(ErrorCode.INVALID_TOKEN);
        }

        RefreshToken refreshTokenEntity = refreshTokenRepository.findByRefreshToken(refreshToken)
                .orElseThrow(() -> new CustomException(ErrorCode.NOT_EXIST_TOKEN));

        if(!refreshToken.equals(refreshTokenEntity.getRefreshToken())){
            throw new CustomException(ErrorCode.ALREADY_LOGGED_OUT_USER);
        }
        refreshTokenRepository.delete(refreshTokenEntity);
        jwtUtil.addBlackList(accessToken);
        return true;
    }

    public String findEmail(FindEmailRequest findEmailRequest){
        return memberRepository
                .findByNameAndStudentIdAndType(findEmailRequest.name(), findEmailRequest.studentId(), LoginType.GENERAL)
                .orElseThrow(()-> new CustomException(ErrorCode.USER_NOT_FOUND)).getEmail();

    }

    public boolean checkMember(CheckMemberRequest checkMemberRequest){
        if(!memberRepository.existsByNameAndEmailAndType(
                checkMemberRequest.name(), checkMemberRequest.email(), LoginType.GENERAL)){
            throw new CustomException(ErrorCode.USER_NOT_FOUND);
        }
        return true;
    }

    @Transactional
    public boolean changePassword(ChangePasswordRequest changePasswordRequest){
        memberRepository.findByEmail(changePasswordRequest.email())
                .map(member -> member.updatePassword(passwordEncoder.encode(changePasswordRequest.newPassword())))
                .orElseThrow(() -> new CustomException(ErrorCode.USER_NOT_FOUND));
        return true;
    }

    private String resolveToken(String token) {
        if(Strings.hasText(token) && token.startsWith(JwtProperties.JWT_TYPE)){
            return token.substring(7);
        }
        return null;
    }


    @Transactional
    public Boolean withdrawal(String refreshToken) {

        if (!Strings.hasText(refreshToken)) {
            throw new CustomException(ErrorCode.NOT_EXIST_TOKEN);
        }
        if (!jwtUtil.validateToken(refreshToken)) {
            throw new CustomException(ErrorCode.INVALID_TOKEN);
        }

        RefreshToken refreshTokenEntity = refreshTokenRepository.findByRefreshToken(refreshToken)
                .orElseThrow(() -> new CustomException(ErrorCode.NOT_EXIST_TOKEN));

        String email = jwtUtil.getEmail(refreshToken);
        LoginType type = jwtUtil.getLoginType(refreshToken);

        Member member = memberRepository.findByEmailAndType(email, type)
                .orElseThrow(() -> new CustomException(ErrorCode.USER_NOT_FOUND));

        refreshTokenRepository.delete(refreshTokenEntity);
        memberRepository.delete(member);

        return true;
    }
}