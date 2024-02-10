package com.hit.community.service;

import com.hit.community.entity.Mail;
import com.hit.community.error.CustomException;
import com.hit.community.error.ErrorCode;
import jakarta.mail.Message;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;


@RequiredArgsConstructor
@Service
public class MailService {

    private final JavaMailSender mailSender;
    private static final String SENDER = "sunnamgung8@naver.com";

    public Mail createMessage(String toEmail){
        MimeMessage message = mailSender.createMimeMessage();
        String confirmCode = getConfirmCode();
        try{
            String subject = "HCC 인증 메일입니다.";

            String html = "";
            html += "<div style=\"font-family: 'Apple SD Gothic Neo', 'sans-serif' !important; width: 540px; height: 600px; border-top: 4px solid #02b875; margin: 100px auto; padding: 30px 0; box-sizing: border-box;\">\n" +
                    "\t<h1 style=\"margin: 0; padding: 0 5px; font-size: 28px; font-weight: 400;\">\n" +
                    "\t\t<span style=\"font-size: 15px; margin: 0 0 10px 3px;\">HCC</span><br />\n" +
                    "\t\t<span style=\"color: #02b875;\">메일인증</span> 안내입니다.\n" +
                    "\t</h1>\n" +
                    "\t<p style=\"font-size: 16px; line-height: 26px; margin-top: 50px; padding: 0 5px;\">\n" +
                    "\t\t안녕하세요.<br />\n" +
                    "\t\tHCC에 가입해 주셔서 진심으로 감사드립니다.<br />\n" +
                    "\t\t인증번호: ";
            html += confirmCode;
            html += "<span style=\"font-size: 24px;\"></span>입니다.";

            message.addRecipients(Message.RecipientType.TO,toEmail);
            message.setFrom(new InternetAddress(SENDER, "HIT"));
            message.setSubject(subject);
            message.setText(html, "utf-8", "html");
        } catch (UnsupportedEncodingException e){
            throw new CustomException(ErrorCode.UN_SUPPORTED_ENCODING);
        } catch (Exception e){
            throw new CustomException(ErrorCode.MESSAGING);
        }

        mailSender.send(message);
        return Mail.builder().toEmail(toEmail).confirmCode(confirmCode).build();

    }

    private String getConfirmCode(){
        int length = 6;

        try { SecureRandom random = SecureRandom.getInstanceStrong();
            StringBuilder builder = new StringBuilder();
            for (int i = 0; i < length; i++) {
                builder.append(random.nextInt(10));
            }
            return builder.toString();
        }catch (NoSuchAlgorithmException e){
            throw new CustomException(ErrorCode.NO_SUCH_ALGORITHM);
        }
    }
}
