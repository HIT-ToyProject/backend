package com.hit.community.custom;

import com.hit.community.dto.OAuthAttribute;
import com.hit.community.entity.LoginType;
import com.hit.community.entity.Member;
import com.hit.community.entity.Role;
import com.hit.community.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.Optional;

@RequiredArgsConstructor
@Service
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final MemberRepository memberRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

        OAuth2UserService<OAuth2UserRequest, OAuth2User> delegate =
                new DefaultOAuth2UserService();

        OAuth2User oAuth2User = delegate.loadUser(userRequest);

        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        String userNameAttributeName = userRequest.getClientRegistration()
                .getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName();

        OAuthAttribute oAuthAttribute =
                OAuthAttribute.of(registrationId, oAuth2User.getAttributes());
        Member member = updateOrSave(oAuthAttribute);

        return new CustomOAuth2User(
                    Collections.singleton(
                            new SimpleGrantedAuthority(member.getRole().name())
                    ),
                oAuthAttribute.getAttributes(),
                userNameAttributeName,
                member.getEmail(),
                member.getRole(),
                member.getType()
            );
    }

    private Member updateOrSave(OAuthAttribute authAttribute) {

        Optional<Member> opMember = memberRepository.findByEmailAndType(authAttribute.getEmail(), authAttribute.getType());

        Member member = opMember.map(entity ->
                        entity.update(
                                authAttribute.getName(),
                                authAttribute.getEmail(),
                                authAttribute.getProfile(),
                                Role.ROLE_USER,
                                authAttribute.getType()
                )
        ).orElse(authAttribute.toEntity());
        memberRepository.save(member);
        return member;

    }
}
