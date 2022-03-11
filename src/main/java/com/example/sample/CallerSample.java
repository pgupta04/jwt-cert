package com.example.sample;

import java.io.DataInputStream;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;

public class CallerSample {

    public String getToken(){
        CertificateDetails certDetails = CertificateUtil.getCertificateDetails("C:\\path_for_pem.jks", "created_pass");
        System.out.println(certDetails.getPrivateKey());
        System.out.println(certDetails.getX509Certificate());
        IDTokenGenerator tokenGenerator = new IDTokenGenerator(certDetails.getPrivateKey(),certDetails.getX509Certificate());
        String token = tokenGenerator.generateToken("client", "otherParam");
        return token;
    }

    public static void main(String[] args) {
        getToken_v2();
    }
    public static String getToken_v2(){
        String certPath = "/Users/pg/work/projects/java/jwt-cert/TestServer.pem";
        String keyPath = "/Users/pg/work/projects/java/jwt-cert/TestServer.key";

        X509Certificate cer = null;
        PrivateKey privateKey = null;
        try {
            CertificateFactory fact = CertificateFactory.getInstance("X.509");
            FileInputStream is = new FileInputStream(certPath);
            cer = (X509Certificate) fact.generateCertificate(is);
            PublicKey key = cer.getPublicKey();
            is.close();
        } catch (Exception ex){
            ex.printStackTrace();
        }
        try {
            Path path = Paths.get(keyPath);
            byte[] privKeyByteArray = Files.readAllBytes(path);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privKeyByteArray);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            privateKey= keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            e.printStackTrace();
        }
        IDTokenGenerator tokenGenerator = new IDTokenGenerator(privateKey,cer);
        String token = tokenGenerator.generateToken("client", "otherParam");
        return token;
    }

}
