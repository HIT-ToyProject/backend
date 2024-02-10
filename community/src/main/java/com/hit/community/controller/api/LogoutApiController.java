package com.hit.community.controller.api;

import com.hit.community.dto.ApiDataResponse;
import com.hit.community.service.MemberService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RestController
public class LogoutApiController {

    private final MemberService memberService;

    @PostMapping("/logout/proc")
    public ApiDataResponse<Boolean> logout(HttpServletRequest request){
        return ApiDataResponse.of(memberService.logout(request));
    }

}
