package com.example.sample;

import java.security.Key;
import java.security.cert.X509Certificate;

public class IDTokenGenerator {

    private Key privateKey;
    private X509Certificate publicCert;

    public IDTokenGenerator(Key privateKey, X509Certificate publicCert) {
        this.privateKey = privateKey;
        this.publicCert = publicCert;
    }

    public String generateToken(String client, String otherVal){
        return "Token";
    }
}
