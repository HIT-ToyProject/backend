package com.hit.community.dto;


import com.hit.community.entity.LoginType;
import com.hit.community.entity.Member;
import com.hit.community.entity.Role;
import lombok.Builder;
import lombok.Getter;

import java.util.Map;

@Getter
public class OAuthAttribute {

    private Map<String, Object> attributes;
    private String nameAttributeKey;
    private String name;
    private String email;
    private String profile;
    private String provider;
    private Role role;
    private LoginType type;

    @Builder
    public OAuthAttribute(Map<String, Object> attributes, String nameAttributeKey,
                          String name, String email, String profile,Role role,
                          String provider, LoginType type) {
        this.attributes = attributes;
        this.nameAttributeKey = nameAttributeKey;
        this.name = name;
        this.email = email;
        this.profile = profile;
        this.role = role;
        this.provider = provider;
        this.type = type;
    }

    public static OAuthAttribute of(
            String provider,
            Map<String, Object> attributes
    ){
        
        switch (provider){
            case "google":
                return ofGoogle(provider, attributes);
            case "naver":
                return ofNaver(provider, attributes);

            case "kakao":
                return ofKakao(provider, attributes);
            default: throw new RuntimeException();
        }

    }



    private static OAuthAttribute ofGoogle(
            String provider,
            Map<String, Object> attributes
    ){

        return OAuthAttribute.builder()
                .attributes(attributes)
                .nameAttributeKey("sub")
                .name((String)attributes.get("name"))
                .email((String)attributes.get("email"))
                .profile((String)attributes.get("picture"))
                .role(Role.ROLE_ADMIN)
                .provider(provider)
                .type(LoginType.GOOGLE)
                .build();
    }



    private static OAuthAttribute ofNaver(
            String provider,
            Map<String, Object> attributes
    ){

        Map<String, Object> response = (Map<String, Object>)attributes.get("response");

        return OAuthAttribute.builder()
                .attributes(attributes)
                .nameAttributeKey("response")
                .name((String)response.get("name"))
                .email((String)response.get("email"))
                .profile((String)response.get("profile_image"))
                .role(Role.ROLE_ADMIN)
                .provider(provider)
                .type(LoginType.NAVER)
                .build();
    }

    private static OAuthAttribute ofKakao(String provider, Map<String, Object> attributes) {
        System.out.println(attributes);
        Map<String, Object> kakaoAccount = (Map<String, Object>)attributes.get("kakao_account");
        Map<String, Object> kakaoProfile = (Map<String, Object>)kakaoAccount.get("profile");

        return OAuthAttribute.builder()
                .attributes(attributes)
                .nameAttributeKey("id")
                .name((String)kakaoProfile.get("nickname"))
                .email((String)kakaoAccount.get("email"))
                .profile((String)kakaoProfile.get("profile_image_url"))
                .role(Role.ROLE_ADMIN)
                .provider(provider)
                .type(LoginType.KAKAO)
                .build();
    }

    public Member toEntity(){
        return Member.builder()
                .name(name)
                .email(email)
                .profile(profile)
                .role(Role.ROLE_GUEST)
                .type(type)
                .build();
    }

}
