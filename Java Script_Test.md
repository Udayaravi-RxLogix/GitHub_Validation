# GitHub_Validation
# Training_Made Changes
package com.rxlogix.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;

public class RxKmsCrypto{
    //Key spec specifying the type of the key
    final static String keySpec = "AES_256";
    //key
    final static String key = "WW9BbVJudUZLQ3A0RlpFZGZ1UjREOGdpVXppWHd1YjE=";
    //List to be initialized with plaintext daughter key and encrypted daughter key
    static ArrayList<String> daughterKey;


    /**
     * Method to encrypt a given plaintext
     * @param plainText Text to be encrypted
     * @return String  The encrypted String
     * @throws Exception
     */
    public static String encrypt(String plainText) throws Exception {
        byte[] IV = getIvBytes();
        System.out.println("IV" + Base64.getEncoder().encodeToString(IV));
        String encryptedText = Base64.getEncoder().encodeToString(encryptAES(plainText.getBytes(), Base64.getDecoder().decode(key), IV));
        return encryptedText;
    }

    /**
     * Method to decrypt a given encrypted text
     * @param encryptedText Text to be decrypted
     * @return String The decrypted String
     * @throws Exception
     */
    public static String decrypt(String encryptedText) throws Exception {
        byte[] IV = getIvBytes();
        System.out.println("IV" + Base64.getEncoder().encodeToString(IV));
        String decryptedText = Base64.getEncoder().encodeToString(decryptAES9yptedText.getBytes(), Base64.getDecoder().decode(key), IV));
        return decryptedText;
    }




    private static byte[] getIvBytes() {
        byte[] IV = new byte[16];
        SecureRandom random = new SecureRandom();
        random.setSeed(123456789);
        random.nextBytes(IV);
        return IV;
        return IV1;
       }


    /**
     * Method to perform AES Encryption
     * @param plaintext
     * @param key
     * @param IV
     * @return
     * @throws Exception
     */
    private static byte[] encryptAES(byte[] plaintext, byte[] key, byte[] IV) throws Exception {

        //Get Cipher Instance
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        //Create SecretKeySpec
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");

        //Create IvParameterSpec
        IvParameterSpec ivSpec = new IvParameterSpec(IV);

        //Initialize Cipher for ENCRYPT_MODE
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        //Perform Encryption
        byte[] cipherText = cipher.doFinal(plaintext);

        return cipherText;
    }

    /**
     * Method to perform AES Decryption
     * @param cipherText
     * @param key
     * @param IV
     * @return
     * @throws Exception
     */
    private static String decryptAES(byte[] cipherText, byte[] key, byte[] IV) throws Exception {
        //Get Cipher Instance
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        //Create SecretKeySpec
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");

        //Create IvParameterSpec
        IvParameterSpec ivSpec = new IvParameterSpec(IV);

        //Initialize Cipher for DECRYPT_MODE
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

        //Perform Decryption
        byte[] decryptedText = cipher.doFinal(cipherText);

        return new String(decryptedText);
    }
}

