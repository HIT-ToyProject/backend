package com.hit.community.entity;

import com.hit.community.controller.api.SignUpOAuth2Request;
import com.hit.community.dto.SignUpRequest;
import jakarta.persistence.*;
import lombok.*;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
public class Member extends BaseTime {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(nullable = false)
    private String name;
    @Column(nullable = false)
    private String email;
    
    private String profile;
    private String studentId;
    private String password;
    private String nickName;
    private String major;
    private String gender;


    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    private Role role;

    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    private LoginType type;

    @Builder
    public Member(
            String name, String email, String profile,
            String studentId, String password, String nickName,
            String major, String gender, Role role, LoginType type)
    {
        this.name = name;
        this.email = email;
        this.profile = profile;
        this.studentId = studentId;
        this.password = password;
        this.nickName = nickName;
        this.major = major;
        this.gender = gender;
        this.role = role;
        this.type = type;
    }

    @Builder
    public Member(String name, String email, String profile, Role role, LoginType type) {
        this.name = name;
        this.email = email;
        this.profile = profile;
        this.role = role;
        this.type = type;
    }

    public static Member of(Member member){
        return Member.builder()
                .name(member.getName())
                .email(member.getEmail())
                .profile(member.getProfile())
                .role(member.getRole())
                .type(member.getType())
                .build();
    }

    public Member update(String name, String email, String profile, Role role, LoginType type) {
        if(name != null){
            this.name = name;
        }
        if(email != null){
            this.email = email;
        }
        if(profile != null){
            this.profile = profile;
        }
        if (role != null){
            this.role = role;
        }
        if(type != null){
            this.type = type;
        }
        return this;
    }

    public Member toEntity(SignUpOAuth2Request request){
        this.email = request.email();
        this.name = request.name();
        this.profile = request.profile();
        this.password = null;
        this.studentId = request.studentId();
        this.nickName = request.nickName();
        this.major = request.major();
        this.gender = request.gender();
        return this;
    }

    public Member updatePassword(String newPassword) {
        if(newPassword != null){
            this.password = newPassword;
        }
        return this;
    }

}
