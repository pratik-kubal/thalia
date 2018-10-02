package com.pratik;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.security.*;

public class Main {

    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
	// write your code here

        // Init stopwatch

        // Read file
        long startTime = System.currentTimeMillis();
        AES_CBC_128("file-small.bin");
        //AES_CBC_128_DEC(aesCBCKey_128,"file-small.bin");
        //AES_CBC_128("file-large.bin");
        //testFile();
        long stopTime = System.currentTimeMillis();
        long elapsedTime = stopTime - startTime;
        System.out.println("Time taken to run the whole program in seconds: "+(float)elapsedTime/1000);
    }

    public static void AES_CBC_128(String filepath) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        //File path
        String outputPath = "src/com/pratik/Data/AES_CBC_128_EN-"+filepath;
        OutputStream outputstream = new FileOutputStream(outputPath);
        filepath = "src/com/pratik/Data/"+filepath;
        InputStream inputstream = new FileInputStream(filepath);
        int size = inputstream.available();

        byte[] data      = new byte[16];
        int bytesRead = inputstream.read(data,0,16);
        int i = 1;

        //int bytesRead=0;

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

        // IV
        byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        IvParameterSpec ivspec = new IvParameterSpec(iv);

        startTime = System.currentTimeMillis();
        // Make Instance of the algorithm
        Cipher aesCBC = Cipher. getInstance("AES/CBC/NoPadding");
        // Init the algorithm
        aesCBC.init(Cipher.ENCRYPT_MODE, aesCBCKey,ivspec);

        // Use update for previous block and final for the last block while using chaining

        // First Encryption
        byte[] result = aesCBC.update(data);
        outputstream.write(result);

        while(bytesRead != -1){
            bytesRead = inputstream.read(data,0,16);
            //System.out.println(inputstream.available());
            if(bytesRead != -1){
                if(inputstream.available() > 0){
                    result = aesCBC.update(data);
                }else if(inputstream.available() == 0){
                    result = aesCBC.doFinal(data);
                }
                outputstream.write(result);
            }
            i++;
        }
        stopTime = System.currentTimeMillis();
        elapsedTime = stopTime - startTime;
        System.out.println("Time Taken for Encryption is: "+(float)elapsedTime/1000);
        System.out.println("Encryption Speed per Byte:"+(float)elapsedTime/size);
        // File Handling maintenance
        outputstream.flush();
        outputstream.close();
        inputstream.close();

        System.out.println();
        System.out.println("Decryption");
        InputStream DECinputstream = new FileInputStream("src/com/pratik/Data/AES_CBC_128_EN-file-small.bin");
        OutputStream DECoutputstream = new FileOutputStream("src/com/pratik/Data/AES_CBC_128_DEC-file-small.bin");

        size = DECinputstream.available();

        data      = new byte[16];
        bytesRead = DECinputstream.read(data,0,16);
        i = 1;

        // IV
        //byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        //IvParameterSpec ivspec = new IvParameterSpec(iv);

        startTime = System.currentTimeMillis();
        // Init the algorithm
        aesCBC.init(Cipher.DECRYPT_MODE, aesCBCKey,ivspec);

        // First Encryption
        result = aesCBC.update(data);
        DECoutputstream.write(result);

        while(bytesRead != -1){
            bytesRead = DECinputstream.read(data,0,16);
            System.out.println(DECinputstream.available());
            if(bytesRead != -1){
                if(DECinputstream.available() > 0){
                    result = aesCBC.update(data);
                }else if(DECinputstream.available() == 0){
                    System.out.println("final");
                    result = aesCBC.doFinal(data);
                }
                DECoutputstream.write(result);
            }
            i++;
        }
        stopTime = System.currentTimeMillis();
        elapsedTime = stopTime - startTime;
        System.out.println("Time Taken for Encryption is: "+(float)elapsedTime/1000);
        System.out.println("Encryption Speed per Byte:"+(float)elapsedTime/size);
        // File Handling maintenance
        outputstream.flush();
        outputstream.close();
        inputstream.close();
    }

    public static void AES_CBC_128_DEC(SecretKey aesCBCKey,String filepath) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        // Decryption
        // Streaming the encrypted file
        System.out.println();
        System.out.println("Decryption");
        InputStream inputstream = new FileInputStream("src/com/pratik/Data/AES_CBC_128_EN-"+filepath);
        OutputStream outputstream = new FileOutputStream("src/com/pratik/Data/AES_CBC_128_DEC-"+filepath);

        int size = inputstream.available();

        byte[] data      = new byte[16];
        int bytesRead = inputstream.read(data,0,16);
        int i = 1;

        // IV
        byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        IvParameterSpec ivspec = new IvParameterSpec(iv);

        long startTime = System.currentTimeMillis();
        // Make Instance of the algorithm
        Cipher aesCBC = Cipher. getInstance("AES/CBC/NoPadding");
        // Init the algorithm
        aesCBC.init(Cipher.DECRYPT_MODE, aesCBCKey,ivspec);

        // First Encryption
        byte[] result = aesCBC.update(data);
        outputstream.write(result);

        while(bytesRead != -1){
            bytesRead = inputstream.read(data,0,16);
            System.out.println(inputstream.available());
            if(bytesRead != -1){
                if(inputstream.available() > 16){
                    result = aesCBC.update(data);
                }else if(inputstream.available() != 0){
                    System.out.println("final");
                    result = aesCBC.doFinal(data);
                }
                outputstream.write(result);
            }
            i++;
        }
        long stopTime = System.currentTimeMillis();
        long elapsedTime = stopTime - startTime;
        System.out.println("Time Taken for Encryption is: "+(float)elapsedTime/1000);
        System.out.println("Encryption Speed per Byte:"+(float)elapsedTime/size);
        // File Handling maintenance
        outputstream.flush();
        outputstream.close();
        inputstream.close();
    }

    public  static void readTestFile() throws IOException {
        InputStream inputstream = new FileInputStream("src/com/pratik/Data/file-small.bin");
        OutputStream outputstream = new FileOutputStream("src/com/pratik/Data/file-small-en.bin");
        byte[] data      = new byte[16];
        int bytesRead = inputstream.read(data,0,16);
        outputstream.write(data);
        int i = 1;
        //int bytesRead=0;
        while(bytesRead != -1){
            System.out.println(bytesRead);
            bytesRead = inputstream.read(data,0,16);
            if(bytesRead != -1){
                outputstream.write(data);
            }
            i++;
        }
        System.out.println(i);
        outputstream.flush();
        outputstream.close();
        inputstream.close();
    }
}
