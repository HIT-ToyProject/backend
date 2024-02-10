package com.hit.community.service;

//@RequiredArgsConstructor
//@Service
//public class AwsMailService {
//
//    private final AmazonSimpleEmailService amazonSimpleEmailService;
//    private static final String SENDER = "sunnamgung8@naver.com";
//
//    public Mail createMessage(String toEmail){
//        SendEmailRequest sendEmailRequest = new SendEmailRequest();
//
//        String confirmCode = getConfirmCode();
//
//            String subject = "HCC 인증 메일입니다.";
//
//            String html = "";
//            html += "<div style=\"font-family: 'Apple SD Gothic Neo', 'sans-serif' !important; width: 540px; height: 600px; border-top: 4px solid #02b875; margin: 100px auto; padding: 30px 0; box-sizing: border-box;\">\n" +
//                    "\t<h1 style=\"margin: 0; padding: 0 5px; font-size: 28px; font-weight: 400;\">\n" +
//                    "\t\t<span style=\"font-size: 15px; margin: 0 0 10px 3px;\">HCC</span><br />\n" +
//                    "\t\t<span style=\"color: #02b875;\">메일인증</span> 안내입니다.\n" +
//                    "\t</h1>\n" +
//                    "\t<p style=\"font-size: 16px; line-height: 26px; margin-top: 50px; padding: 0 5px;\">\n" +
//                    "\t\t안녕하세요.<br />\n" +
//                    "\t\tHCC에 가입해 주셔서 진심으로 감사드립니다.<br />\n" +
//                    "\t\t인증번호: ";
//            html += confirmCode;
//            html += "<span style=\"font-size: 24px;\"></span>입니다.";
//
//            sendEmailRequest.withSource(SENDER)
//                    .withDestination(new Destination().withToAddresses(toEmail))
//                    .withMessage(
//                            new Message()
//                                    .withSubject(createContent(subject))
//                                    .withBody(new Body().withHtml(createContent(html)))
//                    );
//            amazonSimpleEmailService.sendEmail(sendEmailRequest);
//            return Mail.builder().confirmCode(confirmCode).build();
//
//    }
//
//    private Content createContent(String text){
//        return new Content().withCharset(StandardCharsets.UTF_8.name()).withData(text);
//    }
//    private String getConfirmCode(){
//        int length = 6;
//
//        try { SecureRandom random = SecureRandom.getInstanceStrong();
//            StringBuilder builder = new StringBuilder();
//            for (int i = 0; i < length; i++) {
//                builder.append(random.nextInt(10));
//            }
//            return builder.toString();
//        }catch (NoSuchAlgorithmException e){
//            throw new CustomException(ErrorCode.NO_SUCH_ALGORITHM);
//        }
//    }
//}
