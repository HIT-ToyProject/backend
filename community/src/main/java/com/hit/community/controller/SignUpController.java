package com.hit.community.controller;

import com.hit.community.dto.SignUpOAuth2Response;
import com.hit.community.entity.LoginType;
import com.hit.community.service.MemberService;
import lombok.RequiredArgsConstructor;
import org.apache.logging.log4j.util.Strings;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@RequiredArgsConstructor
@Controller
public class SignUpController {
    private final MemberService memberService;


    @GetMapping("/signUp")
    public String oauth2SignUpForm(
            Model model,
            @RequestParam(required = false) String email,
            @RequestParam(required = false) String type
            ){

            if(Strings.isBlank(email) && Strings.isBlank(type)){
                return "signUp";
            }
            LoginType loginType = LoginType.valueOf(type);
            SignUpOAuth2Response signUpOAuth2Response = memberService.getOAuth2Member(email, loginType);
            model.addAttribute("member", signUpOAuth2Response);
        return "oAuth2SignUp";
    }

}
