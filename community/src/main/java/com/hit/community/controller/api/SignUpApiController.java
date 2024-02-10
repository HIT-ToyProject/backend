package com.hit.community.controller.api;

import com.hit.community.dto.ApiDataResponse;
import com.hit.community.dto.ConfirmCodeRequest;
import com.hit.community.dto.SignUpRequest;
import com.hit.community.service.MemberService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RequiredArgsConstructor
@RestController
public class SignUpApiController {

    private final MemberService memberService;


    @PostMapping("/signUp")
    public ApiDataResponse<Boolean> signUp(
            @Valid @RequestBody SignUpRequest signUpRequest){
        return ApiDataResponse.of(memberService.saveMember(signUpRequest));
    }
    @PostMapping("/signUp/oauth2")
    public ApiDataResponse<Boolean> signUpOauth2(
            @Valid @RequestBody SignUpOAuth2Request signUpOAuth2Request){
        return ApiDataResponse.of(memberService.saveOauth2Member(signUpOAuth2Request));
    }

    @PostMapping("/signUp/send/{email}")
    public ApiDataResponse<Boolean> sendCodeToEmail(@PathVariable String email){
        boolean isTrue = memberService.sendCodeToEmail(email);
        return ApiDataResponse.of(isTrue);
    }

    @GetMapping("/signUp/check/confirmCode")
    public ApiDataResponse<Boolean> confirmCode(@RequestBody ConfirmCodeRequest confirmCodeRequest){
        boolean isTrue = memberService.checkConfirmCode(confirmCodeRequest);
        return ApiDataResponse.of(isTrue);
    }
}
