package com.hit.community.custom;

import com.hit.community.entity.Member;
import com.hit.community.error.CustomException;
import com.hit.community.error.ErrorCode;
import com.hit.community.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@RequiredArgsConstructor
@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final MemberRepository memberRepository;

    @Override
    public UserDetails loadUserByUsername(String email){
        Optional<Member> opMember = memberRepository.findByEmail(email);
        Member member = opMember.orElseThrow(()-> new CustomException(ErrorCode.EMAIL_OR_PASSWORD_NOT_FOUND));
        return new CustomUserDetails(member);
    }
}
