package com.hit.community.repository;

import com.hit.community.entity.Member;
import com.hit.community.entity.MemberInfo;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;

public interface MemberInfoRepository extends JpaRepository<MemberInfo, Long> {

    @Query("select m from Member m join fetch m.memberInfo")
    Optional<Member> findByEmail(String email);
}
