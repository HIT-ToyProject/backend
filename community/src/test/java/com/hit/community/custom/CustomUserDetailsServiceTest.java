package com.hit.community.custom;

import com.hit.community.entity.Member;
import com.hit.community.entity.Role;
import com.hit.community.error.CustomException;
import com.hit.community.error.ErrorCode;
import com.hit.community.repository.MemberRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Optional;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;

@ExtendWith(MockitoExtension.class)
class CustomUserDetailsServiceTest {
    @Mock
    private MemberRepository memberRepository;
    @InjectMocks
    private CustomUserDetailsService userDetailsService;


    @Test
    @DisplayName("회원 정보 존재 유무 테스트 - 성공")
    void loadUserByUsernameSuccessTest() throws Exception
    {
        String email = "email@naver.com";
        Member member = createMember();
        //given
        given(memberRepository.findByEmail(email))
                .willReturn(Optional.of(member));
        //when
        UserDetails userDetails = userDetailsService.loadUserByUsername(email);
        //then
        assertThat(userDetails).isNotNull();
        assertThat(userDetails).hasFieldOrPropertyWithValue("username", member.getEmail());
        assertThat(userDetails).hasFieldOrPropertyWithValue("password", member.getPassword());

        then(memberRepository).should().findByEmail(email);
    }
    @Test
    @DisplayName("회원 정보 존재 유무 테스트 - 실패 (회원 정보 없음)")
    void loadUserByUsernameFailureTest() throws Exception
    {
        String email = "email@naver.com";
        //given
        given(memberRepository.findByEmail(email))
                .willReturn(Optional.empty());
        //when
        CustomException exception = (CustomException) catchRuntimeException(()->userDetailsService.loadUserByUsername(email));
        //then
        assertThat(exception).isInstanceOf(CustomException.class);
        assertThat(exception).hasMessageContaining(ErrorCode.EMAIL_OR_PASSWORD_NOT_FOUND.getMessage());
        then(memberRepository).should().findByEmail(email);
    }
    private Member createMember() {
        return Member.builder()
                .email("email@naver.com")
                .name("name")
                .password("password123*")
                .profile("profile")
                .nickName("nickName")
                .studentId("L190201201")
                .gender("male")
                .major("major")
                .role(Role.ROLE_USER)
                .build();
    }

}