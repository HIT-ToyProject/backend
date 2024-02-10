package com.hit.community.custom;

import com.hit.community.entity.Member;
import com.hit.community.entity.Role;
import com.hit.community.error.CustomException;
import com.hit.community.error.ErrorCode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchRuntimeException;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;

@ExtendWith(MockitoExtension.class)
class CustomProviderTest {

    @Mock
    private CustomUserDetailsService userDetailsService;
    @Mock
    private PasswordEncoder passwordEncoder;
    @InjectMocks
    private CustomAuthenticationProvider customAuthenticationProvider;

    @BeforeEach
    void init(){
        SecurityContextHolder.getContext()
                .setAuthentication(new UsernamePasswordAuthenticationToken("email@naver.com","password123*"));
    }

    
    @Test
    @DisplayName("회원 검증 테스트 - 성공")
    void authenticateSuccessTest() throws Exception
    {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String email = (String) authentication.getPrincipal();
        String password = (String) authentication.getCredentials();
        Member member = createMember();
        CustomUserDetails userDetails = new CustomUserDetails(member);

        //given
        given(userDetailsService.loadUserByUsername(email)).willReturn(userDetails);
        given(passwordEncoder.matches(password, userDetails.getPassword())).willReturn(true);

        //when
        Authentication authenticate = customAuthenticationProvider.authenticate(authentication);

        //then
        assertThat(authenticate).hasFieldOrPropertyWithValue("principal", userDetails.getUsername());
        assertThat(authenticate).hasFieldOrPropertyWithValue("credentials", userDetails.getPassword());
        assertThat(
                authenticate.getAuthorities().stream().map(GrantedAuthority::getAuthority).findFirst().toString()
        )
                .isEqualTo(
                        userDetails.getAuthorities().stream().map(GrantedAuthority::getAuthority).findFirst().toString()
                );
        then(userDetailsService).should().loadUserByUsername(email);
        then(passwordEncoder).should().matches(password, userDetails.getPassword());
    }

    @Test
    @DisplayName("회원 검증 테스트 - 실패")
    void authenticateFailureTest() throws Exception
    {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String email = (String) authentication.getPrincipal();
        String password = (String) authentication.getCredentials();
        Member member = createMember();
        CustomUserDetails userDetails = new CustomUserDetails(member);

        //given
        given(userDetailsService.loadUserByUsername(email)).willReturn(userDetails);
        given(passwordEncoder.matches(password, userDetails.getPassword())).willReturn(false);
        //when
        CustomException exception = (CustomException) catchRuntimeException(()-> customAuthenticationProvider.authenticate(authentication));

        //then
        assertThat(exception).isInstanceOf(CustomException.class);
        assertThat(exception).hasMessageContaining(ErrorCode.EMAIL_OR_PASSWORD_NOT_FOUND.getMessage());
        then(userDetailsService).should().loadUserByUsername(email);
        then(passwordEncoder).should().matches(password, userDetails.getPassword());
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