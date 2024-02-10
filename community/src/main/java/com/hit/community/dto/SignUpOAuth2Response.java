package com.hit.community.dto;

import com.hit.community.entity.Member;

public record SignUpOAuth2Response(
        String name,
        String email,
        String profile
) {

    public static SignUpOAuth2Response of(
            String name,
            String email,
            String profile
    ){
        return new SignUpOAuth2Response(name, email, profile);
    }

    public static SignUpOAuth2Response fromMemberResponse(Member member){
        return SignUpOAuth2Response.of(
                member.getName(),
                member.getEmail(),
                member.getProfile()
        );
    }
}
