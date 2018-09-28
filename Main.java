package com.pratik;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class Main{

    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
	// write your code here

        // Init stopwatch

        // Read file
        long startTime = System.currentTimeMillis();
        AES_CBC_128();
        long stopTime = System.currentTimeMillis();
        long elapsedTime = stopTime - startTime;
        System.out.println("Time taken to run the whole program in seconds: "+(float)elapsedTime/1000);
    }

    public static void AES_CBC_128() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        // Make Instance of the algorithm
        Cipher aesCBC = Cipher. getInstance("AES/CBC/NoPadding");

        // Generate Key
        long startTime = System.currentTimeMillis();
        KeyGenerator aesCBCKeyInstance = KeyGenerator.getInstance("AES");
        SecureRandom random_key = new SecureRandom();
        int keySize= 128;
        aesCBCKeyInstance.init(keySize,random_key);
        SecretKey aesCBCKey = aesCBCKeyInstance.generateKey();
        long stopTime = System.currentTimeMillis();
        long elapsedTime = stopTime - startTime;
        System.out.println("Time taken to Generate the Key in Seconds: "+(float)elapsedTime/1000);

        // Init the algorithm
        aesCBC.init(Cipher.ENCRYPT_MODE, aesCBCKey);

        // Use update for previous block and final for the last block while using chaining
    }
}
