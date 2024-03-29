package com.hit.community.entity;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
public class Member extends BaseTime {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    @Column(nullable = false)
    private String name;

    @Column(nullable = false, unique = false)
    private String email;

    @Column(nullable = false, unique = false)
    private String profile;

    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    private Role role;

    @OneToOne(mappedBy = "member")
    private MemberInfo memberInfo;

    @Builder
    public Member(String name, String email, String profile, Role role, MemberInfo memberInfo) {
        this.name = name;
        this.email = email;
        this.profile = profile;
        this.role = role;
        this.memberInfo = memberInfo;
    }


    public static Member of(Member member){
        return Member.builder()
                .name(member.getName())
                .email(member.getEmail())
                .profile(member.getProfile())
                .role(member.getRole())
                .build();
    }

    public Member update(String name, String email, String profile, Role role) {
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
        return this;
    }

    public void addInfo(MemberInfo memberInfo) {
        this.memberInfo = memberInfo;
    }
}
