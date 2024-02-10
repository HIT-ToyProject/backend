package com.hit.community.repository;

import com.hit.community.entity.Mail;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface MailRepository extends CrudRepository<Mail, Long> {

    Optional<Mail> findByToEmail(String toEmail);
}
