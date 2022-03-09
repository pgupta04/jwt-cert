package com.example.sample;

public class CallerSample {

    public String getToken(){
        CertificateDetails certDetails = CertificateUtil.getCertificateDetails("C:\\path_for_pem.jks", "created_pass");
        System.out.println(certDetails.getPrivateKey());
        System.out.println(certDetails.getX509Certificate());
        IDTokenGenerator tokenGenerator = new IDTokenGenerator(certDetails.getPrivateKey(),certDetails.getX509Certificate());
        String token = tokenGenerator.generateToken("client", "otherParam");
        return token;
    }
}
