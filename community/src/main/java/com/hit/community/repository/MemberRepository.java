package com.hit.community.repository;

import com.hit.community.entity.LoginType;
import com.hit.community.entity.Member;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface MemberRepository extends JpaRepository<Member, Long> {

    Optional<Member> findByEmail(String email);

    Optional<Member> findByNameAndStudentIdAndType(String name, String studentId, LoginType type);
    Optional<Member> findByEmailAndType(String email, LoginType type);

    boolean existsByNameAndEmailAndType(String name, String email, LoginType type);
    boolean existsByEmail(String email);

    boolean existsByNickName(String nickName);
    boolean existsByPassword(String password);
    boolean existsByStudentId(String studentId);
}
