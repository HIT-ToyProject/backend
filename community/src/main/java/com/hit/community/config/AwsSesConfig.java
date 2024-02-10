package com.hit.community.config;

//@Configuration
//public class AwsSesConfig {
//
//    private final String accessKey;
//    private final String secretKey;
//
//    public AwsSesConfig(
//            @Value("${aws.ses.accessKey}")
//            String accessKey,
//            @Value("${aws.ses.secretKey}")
//            String secretKey) {
//        this.accessKey = accessKey;
//        this.secretKey = secretKey;
//    }
//
//
//    @Bean
//    public AmazonSimpleEmailService amazonSimpleEmailService(){
//        BasicAWSCredentials basicAWSCredentials = new BasicAWSCredentials(accessKey, secretKey);
//        AWSStaticCredentialsProvider awsStaticCredentialsProvider = new AWSStaticCredentialsProvider(basicAWSCredentials);
//
//        return AmazonSimpleEmailServiceClientBuilder.standard()
//                .withCredentials(awsStaticCredentialsProvider)
//                .withRegion(Regions.AP_NORTHEAST_2)
//                .build();
//    }
//}
