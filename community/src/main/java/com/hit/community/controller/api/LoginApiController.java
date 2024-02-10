package com.hit.community.controller.api;

import com.hit.community.dto.*;
import com.hit.community.error.CustomException;
import com.hit.community.error.ErrorCode;
import com.hit.community.properties.JwtProperties;
import com.hit.community.dto.ChangePasswordRequest;
import com.hit.community.dto.CheckMemberRequest;
import com.hit.community.service.MemberService;
import com.hit.community.util.CookieUtil;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RestController
public class LoginApiController {
    
    private final MemberService memberService;


    @PostMapping("/login")
    public ApiDataResponse<JwtResponse> login(
            HttpServletResponse response,
            @RequestBody @Valid LoginRequest loginRequest){

        CustomTokenResponse tokenResponse = memberService.login(loginRequest);
        response.addHeader(JwtProperties.AUTHORIZATION, JwtProperties.JWT_TYPE + tokenResponse.accessToken());
        CookieUtil.addCookies(response, JwtProperties.REFRESH_TOKEN_NAME, tokenResponse.refreshToken());
        return ApiDataResponse.of(JwtResponse.of(loginRequest.email(), tokenResponse.accessToken()));
    }



    @PostMapping("/login/reissue")
    public ApiDataResponse<Boolean> reissue(
            HttpServletRequest request,
            HttpServletResponse response
    ){

        String refreshToken = CookieUtil.getCookie(request, JwtProperties.REFRESH_TOKEN_NAME)
                .map(Cookie::getValue)
                .orElseThrow(()->new CustomException(ErrorCode.NOT_EXIST_TOKEN));

        String accessToken = memberService.reissue(refreshToken);
        response.addHeader(HttpHeaders.AUTHORIZATION, JwtProperties.JWT_TYPE + accessToken);
        return ApiDataResponse.of(true);
    }

    @GetMapping("/login/findEmail")
    public ApiDataResponse<String> findEmail(@RequestBody @Valid FindEmailRequest findEmailRequest){
        return ApiDataResponse.of(memberService.findEmail(findEmailRequest));
    }

    @GetMapping("/login/checkMember")
    public ApiDataResponse<Boolean> checkMember(@RequestBody @Valid CheckMemberRequest checkMemberRequest){
        return ApiDataResponse.of(memberService.checkMember(checkMemberRequest));
    }

    @PostMapping("/login/changePassword")
    public ApiDataResponse<Boolean> changePassword(@RequestBody @Valid ChangePasswordRequest changePasswordRequest){
        return ApiDataResponse.of(memberService.changePassword(changePasswordRequest));
    }

    @PostMapping("/login/withdrawal")
    public ApiDataResponse<Boolean> withdrawal(HttpServletRequest request, HttpServletResponse response){
        String refreshToken =  CookieUtil.getCookie(request, JwtProperties.REFRESH_TOKEN_NAME)
                .map(Cookie::getValue)
                .orElseThrow(()->new CustomException(ErrorCode.NOT_EXIST_TOKEN));
        CookieUtil.deleteCookies(request,response,JwtProperties.REFRESH_TOKEN_NAME);
        return ApiDataResponse.of(memberService.withdrawal(refreshToken));
    }

}
