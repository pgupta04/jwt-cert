package com.example.jwtcert;


import java.io.File;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.text.ParseException;
import java.util.Date;
import java.util.UUID;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;

public class JwtTokenUtil {

    public static void encryptedJsonWebToken()
            throws NoSuchAlgorithmException, InvalidKeySpecException, JOSEException, ParseException, IOException {

        /*****
         * Below code is one way of getting Keys from the certificate installed on the same server.
         * This code can be used in prod
         * ***/
//        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
//        //Initialize key size
//        keyPairGenerator.initialize(2048);
//        // Generate the key pair
//        KeyPair keyPair = keyPairGenerator.genKeyPair();
//
//        // Create KeyFactory and RSA Keys Specs
//        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
//        RSAPublicKeySpec publicKeySpec = keyFactory.getKeySpec(keyPair.getPublic(), RSAPublicKeySpec.class);
//        RSAPrivateKeySpec privateKeySpec = keyFactory.getKeySpec(keyPair.getPrivate(), RSAPrivateKeySpec.class);
//
//        // Generate (and retrieve) RSA Keys from the KeyFactory using Keys Specs
//        RSAPublicKey publicRsaKey = (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
//        RSAPrivateKey privateRsaKey = (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);

        File pemFile = new File(JwtTokenUtil.class.getResource("/pem/public-key.pem").getFile());

        RSAPublicKey publicRsaKey = BouncyCastlePemUtils.readX509PublicKey(pemFile);

        JWTClaimsSet.Builder claimsSet = new JWTClaimsSet.Builder();
        claimsSet.issuer("test-user");
        claimsSet.subject("JWE-Authentication-Example");

        //User specified claims
        claimsSet.claim("appId", "230919131512092005");
        claimsSet.claim("userId", "4431d8dc-2f69-4057-9b83-a59385d18c03");
        claimsSet.claim("role", "Admin");
        claimsSet.claim("applicationType", "WEB");
        claimsSet.claim("clientRemoteAddress", "192.168.1.2");

        claimsSet.expirationTime(new Date(new Date().getTime() + 1000 * 60 * 10));
        claimsSet.notBeforeTime(new Date());
        claimsSet.jwtID(UUID.randomUUID().toString());

        System.out.println("Claim Set : \n" + claimsSet.build());

        // Create the JWE header and specify:
        // RSA-OAEP as the encryption algorithm
        // 128-bit AES/GCM as the encryption method
        JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A128GCM);

        // Initialized the EncryptedJWT object
        EncryptedJWT jwt = new EncryptedJWT(header, claimsSet.build());

        // Create an RSA encrypted with the specified public RSA key
        RSAEncrypter encrypter = new RSAEncrypter(publicRsaKey);

        // Doing the actual encryption
        jwt.encrypt(encrypter);

        // Serialize to JWT compact form
        String jwtString = jwt.serialize();
        System.out.println("");
        System.out.println("========================= Encrypted JWE token ==================================");
        System.out.println("");
        System.out.println("\n JWE token : " + jwtString);
        System.out.println("");

        // In order to read back the data from the token using your private RSA key:
        // parse the JWT text string using EncryptedJWT object
        jwt = EncryptedJWT.parse(jwtString);


        System.out.println("");
        System.out.println(
                "==========================================================================================================");

    }

    public static void main(String[] args) {
        try {
            JwtTokenUtil.encryptedJsonWebToken();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (JOSEException e) {
            e.printStackTrace();
        } catch (ParseException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
