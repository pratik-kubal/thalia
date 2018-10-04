package com.pratik;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.security.*;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;


import org.bouncycastle.jcajce.provider.digest.SHA3;
import org.bouncycastle.jce.provider.BouncyCastleProvider;


public class Main {

    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, SignatureException {
	// Q1.a
        System.out.println("Q1.a");
        // Make Instance of the algorithm
        Cipher aesCBC = Cipher. getInstance("AES/CBC/NoPadding");
        // Generate Key
        SecretKey aes128cbc = genAES128(128);
        IvParameterSpec iv = genIV(aesCBC);
        System.out.println();
        System.out.println("AES 128 Small File:");
        System.out.println("Encrypt");
        encrypt_AES_CBC("file-small.bin",aesCBC,aes128cbc,iv);
        System.out.println("Decrypt");
        decrypt_AES_CBC("file-small.bin",aesCBC,aes128cbc,iv);
        System.out.println();
        System.out.println("AES 128 Large File");
        System.out.println("Encrypt");
        encrypt_AES_CBC("file-large.bin",aesCBC,aes128cbc,iv);
        System.out.println("Decrypt");
        decrypt_AES_CBC("file-large.bin",aesCBC,aes128cbc,iv);


    // Q1.b
        System.out.println();
        System.out.println("Q1.b");
        // Make Instance of the algorithm
        Cipher aesCTR = Cipher. getInstance("AES/CTR/NoPadding");
        // Generate Key
        SecretKey aes128ctr = genAES128(128);
        IvParameterSpec ctrIv128 = genIV(aesCBC);
        System.out.println();
        System.out.println("CTR 128 Small File");
        System.out.println("Encrypt");
        encrypt_AES_CTR("file-small.bin",aesCTR,aes128ctr,ctrIv128);
        System.out.println("Decrypt");
        decrypt_AES_CTR("file-small.bin",aesCTR,aes128ctr,ctrIv128);
        // Decrypt File
        System.out.println();
        System.out.println("CTR 128 Large File");
        System.out.println("Encrypt");
        encrypt_AES_CTR("file-large.bin",aesCTR,aes128ctr,ctrIv128);
        System.out.println("Decrypt");
        decrypt_AES_CTR("file-large.bin",aesCTR,aes128ctr,ctrIv128);
    // Q1.c
        System.out.println();
        System.out.println("Q1.c");
        // Generating 256-bit key
        SecretKey aes256 = genAES128(256);
        IvParameterSpec ctrIv256 = genIV(aesCBC);
        // Encrypt file
        System.out.println();
        System.out.println("CTR 256 Small File");
        System.out.println();
        System.out.println("Encrypt");
        encrypt_AES_CTR("file-small.bin",aesCTR,aes256,ctrIv256);
        System.out.println("Decrypt");
        decrypt_AES_CTR("file-small.bin",aesCTR,aes256,ctrIv256);
        System.out.println();
        System.out.println("CTR 256 Large File");
        // Decrypt File
        System.out.println("Encrypt");
        encrypt_AES_CTR("file-large.bin",aesCTR,aes256,ctrIv256);
        System.out.println("Decrypt");
        decrypt_AES_CTR("file-large.bin",aesCTR,aes256,ctrIv256);
    // Q1.d
        System.out.println("Q1.d");
        System.out.println();
        System.out.println("SHA256: ");
        System.out.println();
        System.out.println("Small File:");
        printHex(hash_256("file-small.bin"));
        System.out.println();
        System.out.println();
        System.out.println("Large File:");
        printHex(hash_256("file-large.bin"));
        System.out.println();
        System.out.println();
        System.out.println("SHA512: ");
        System.out.println();
        System.out.println("Small File:");
        printHex(hash_512("file-small.bin"));
        System.out.println();
        System.out.println();
        System.out.println("Large File:");
        printHex(hash_512("file-large.bin"));
        System.out.println();
        System.out.println();
        System.out.print("SHA3-256: ");
        System.out.println();
        System.out.println("Small File:");
        printHex(hash_sha3256("file-small.bin"));
        System.out.println();
        System.out.println();
        System.out.println("Large File:");
        printHex(hash_sha3256("file-large.bin"));
        System.out.println();
	// Q1.e
        System.out.println();
        System.out.println("Q1.e");
        KeyPair rsakeyPair2048 = genSymmetricKey(2048,"RSA");
        RSAPublicKey rsapublicKey2048 = (RSAPublicKey) rsakeyPair2048.getPublic();
        RSAPrivateKey rsaprivateKey2048 = (RSAPrivateKey) rsakeyPair2048.getPrivate();

        Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
        System.out.println();
        System.out.println("RSA 2048 Small File");
        System.out.println("Encrypt");
        encrypt_rsa("file-small.bin",rsa,rsapublicKey2048,2048);
        System.out.println("Decrypt");
        decrypt_rsa("file-small.bin",rsa,rsaprivateKey2048,2048);
        System.out.println();
        System.out.println("RSA 2048 Large File");
        System.out.println("Encrypt");
        encrypt_rsa("file-large.bin",rsa,rsapublicKey2048,2048);
        System.out.println("Decrypt");
        decrypt_rsa("file-large.bin",rsa,rsaprivateKey2048,2048);
    // Q1.f
        System.out.println();
        System.out.println("Q1.f");
        KeyPair rsakeyPair3072 = genSymmetricKey(3072,"RSA");
        RSAPublicKey rsapublicKey3072 = (RSAPublicKey) rsakeyPair3072.getPublic();
        RSAPrivateKey rsaprivateKey3072 = (RSAPrivateKey) rsakeyPair3072.getPrivate();
        System.out.println();
        System.out.println("RSA 3072 Small File");
        System.out.println("Encrypt");
        encrypt_rsa("file-small.bin",rsa,rsapublicKey3072,3072);
        System.out.println("Decrypt");
        decrypt_rsa("file-small.bin",rsa,rsaprivateKey3072,3072);
        System.out.println("RSA 2048 Large File");
        System.out.println("Encrypt");
        encrypt_rsa("file-large.bin",rsa,rsapublicKey3072,3072);
        System.out.println("Decrypt");
        decrypt_rsa("file-large.bin",rsa,rsaprivateKey3072,3072);
	// Q1.g
        System.out.println();
        System.out.println("Q1.g");
        KeyPair dsakeyPair = genSymmetricKey(2048,"DSA");
        DSAPublicKey dsapublicKey = (DSAPublicKey) dsakeyPair.getPublic();
        DSAPrivateKey dsaprivateKey = (DSAPrivateKey) dsakeyPair.getPrivate();
        Signature dsa = Signature.getInstance("SHA256WithDSA");
        SecureRandom secureRandom2048 = new SecureRandom();
        System.out.println("Time Taken and Digital Signature of small file:");
        System.out.println();
        byte[] dsa_byte;
        dsa_byte = dsa_sign("file-small.bin",dsa,dsaprivateKey,secureRandom2048);
        printHex(dsa_byte);
        System.out.println();
        System.out.println("Time Taken and Digital Signature verification:");
        System.out.println();
        System.out.println(dsa_verify("file-small.bin",dsa_byte,dsa,dsapublicKey));

        System.out.println("Time Taken and Digital Signature of large file:");
        System.out.println();
        SecureRandom secureRandom2048_2 = new SecureRandom();
        dsa_byte = dsa_sign("file-large.bin",dsa,dsaprivateKey,secureRandom2048_2);
        printHex(dsa_byte);
        System.out.println();
        System.out.println("Time Taken and Digital Signature verification:");
        System.out.println();
        System.out.println(dsa_verify("file-large.bin",dsa_byte,dsa,dsapublicKey));

        System.out.println("Time Taken and Opposite Files verification check:");
        System.out.println();
        System.out.println(dsa_verify("file-small.bin",dsa_byte,dsa,dsapublicKey));
    // Q1.h
        System.out.println();
        System.out.println("Q1.h");
        KeyPair dsakeyPair3072 = genSymmetricKey(3072,"DSA");
        DSAPublicKey dsapublicKey3072 = (DSAPublicKey) dsakeyPair3072.getPublic();
        DSAPrivateKey dsaprivateKey3072 = (DSAPrivateKey) dsakeyPair3072.getPrivate();

        SecureRandom secureRandom3072_2 = new SecureRandom();
        System.out.println("Time Taken and Digital Signature of small file:");
        System.out.println();
        dsa_byte = dsa_sign("file-small.bin",dsa,dsaprivateKey3072,secureRandom3072_2);
        System.out.println("Time Taken and Digital Signature of small file:");
        System.out.println();
        dsa_byte = dsa_sign("file-small.bin",dsa,dsaprivateKey3072,secureRandom3072_2);
        printHex(dsa_byte);
        System.out.println("Time Taken and Digital Signature verification:");
        System.out.println();
        System.out.println(dsa_verify("file-small.bin",dsa_byte,dsa,dsapublicKey3072));
        System.out.println();
        System.out.println("Time Taken and Digital Signature of large file:");
        System.out.println();
        dsa_byte = dsa_sign("file-large.bin",dsa,dsaprivateKey3072,secureRandom3072_2);
        printHex(dsa_byte);
        System.out.println();
        System.out.println("Time Taken and Digital Signature verification:");
        System.out.println();
        System.out.println(dsa_verify("file-large.bin",dsa_byte,dsa,dsapublicKey3072));
        System.out.println("Time Taken and Opposite Files verification check:");
        System.out.println();
        System.out.println(dsa_verify("file-small.bin",dsa_byte,dsa,dsapublicKey3072));

    }

    public static SecretKey genAES128(int keySize) throws  NoSuchAlgorithmException{
        long startTime=0,endTime = 0;
        SecretKey aesCBCKey = null;
        for(int i =0;i <1000000;i++){
            startTime= System.nanoTime();
            KeyGenerator aesCBCKeyInstance = KeyGenerator.getInstance("AES");
            SecureRandom random_key = new SecureRandom();
            aesCBCKeyInstance.init(keySize,random_key);
            aesCBCKey = aesCBCKeyInstance.generateKey();
            endTime = System.nanoTime();
        }
        long duration = (endTime - startTime);
        System.out.println("Time Taken to Generate Key of length "+keySize+" is: "+duration+" nanoseconds");
        return aesCBCKey;

    }

    public static KeyPair genSymmetricKey(int keySize,String scheme) throws NoSuchAlgorithmException {
        long startTime = 0,endTime=0;
        KeyPair keyPair = null;
        for (int i =0;i<100;i++){
            startTime= System.nanoTime();
            KeyPairGenerator key = KeyPairGenerator.getInstance(scheme);
            SecureRandom random_key = new SecureRandom();
            key.initialize(keySize,random_key);
            keyPair = key.generateKeyPair();
            endTime = System.nanoTime();
        }

        long duration = (endTime - startTime);
        System.out.println("Time Taken to Generate "+scheme+" Key of length "+keySize+" is: "+duration+" nanoseconds");
        return keyPair;

    }

    public static IvParameterSpec genIV(Cipher instance) throws NoSuchAlgorithmException {
        SecureRandom randomSecureRandom = SecureRandom.getInstance("SHA1PRNG");
        byte[] iv_initial_counter = new byte[instance.getBlockSize()];
        randomSecureRandom.nextBytes(iv_initial_counter);
        IvParameterSpec ivParams = new IvParameterSpec(iv_initial_counter);
        return ivParams;
    }

    public static void encrypt_AES_CBC(String filepath,Cipher instance,SecretKey aesCBCKey,IvParameterSpec iv) throws InvalidKeyException, IOException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        Security.addProvider(new BouncyCastleProvider());
        //File path
        String filename = filepath;
        Cipher aesCBC = instance;
        String outputPath = null;
        int looptime=5;
        outputPath = "./com/pratik/Data/AES_CBC_"+aesCBCKey.getEncoded().length*8+"_EN-"+filepath;

        filepath = "./com/pratik/Data/"+filepath;

        if(filename.equals("file-small.bin")){
            looptime = 10000;
        }
        long startTime=0,stopTime=0,resultTime=0;
        for (int i=0;i<looptime;i++){
            OutputStream outputstream = new FileOutputStream(outputPath);
            InputStream inputstream = new FileInputStream(filepath);
            IvParameterSpec ivspec = iv;

            int size = inputstream.available();

            byte[] data      = new byte[16];
            int bytesRead = inputstream.read(data,0,16);
            //int i = 1;


            // Init the algorithm
            aesCBC.init(Cipher.ENCRYPT_MODE, aesCBCKey,ivspec);
            // First Encryption


            startTime =System.nanoTime();
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
                    stopTime = System.nanoTime();
                }
            }

            // File Handling maintenance
            outputstream.flush();
            outputstream.close();
            inputstream.close();
        }

        resultTime= stopTime-startTime;
        System.out.println("Time Taken is:"+resultTime);
        if(filename.equals("file-small.bin")){
            System.out.println("Speed Per Byte(nanoseconds/Byte):"+resultTime/1024);
        }else if(filename.equals("file-large.bin")){
            System.out.println("Speed Per Byte(nanoseconds/Byte):"+resultTime/1048576);
        }
        System.out.println("CBC Encryption as:"+outputPath);
    }

    public static void decrypt_AES_CBC(String filename,Cipher instance,SecretKey aesCBCKey,IvParameterSpec iv)  throws InvalidKeyException, IOException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        Cipher aesCBC = instance;
        IvParameterSpec ivspec = iv;
        long startTime=0,stopTime=0,resultTime=0;
        String in = "./com/pratik/Data/AES_CBC_"+aesCBCKey.getEncoded().length*8+"_EN-"+filename;
        String out = "./com/pratik/Data/AES_CBC_"+aesCBCKey.getEncoded().length*8+"_DEC-"+filename;
        int looptime = 5;
        if(filename.equals("file-small.bin")){
            looptime = 10000;
        }

        for(int i =0;i<looptime;i++){
            InputStream DECinputstream = new FileInputStream(in);
            OutputStream DECoutputstream = new FileOutputStream(out);
            int size = DECinputstream.available();
            //System.out.println(size);
            byte[] data      = new byte[16];
            int bytesRead = DECinputstream.read(data,0,16);
            aesCBC.init(Cipher.DECRYPT_MODE, aesCBCKey,ivspec);

            // First Encryption

            startTime =System.nanoTime();
            byte[] result = aesCBC.update(data);
            DECoutputstream.write(result);

            while(bytesRead != -1){
                bytesRead = DECinputstream.read(data,0,16);
                //System.out.println(DECinputstream.available());
                if(bytesRead != -1){
                    if(DECinputstream.available() > 0){
                        result = aesCBC.update(data);
                    }else if(DECinputstream.available() == 0){
                        //System.out.println("final");
                        result = aesCBC.doFinal(data);
                    }
                    DECoutputstream.write(result);
                    stopTime = System.nanoTime();
                }
            }
            // File Handling maintenance
            DECoutputstream.flush();
            DECoutputstream.close();
            DECinputstream.close();
        }
        resultTime= stopTime-startTime;
        System.out.println("Time Taken is:"+resultTime);
        if(filename.equals("file-small.bin")){
            System.out.println("Speed Per Byte(nanoseconds/Byte):"+resultTime/1024);
        }else if(filename.equals("file-large.bin")){
            System.out.println("Speed Per Byte(nanoseconds/Byte):"+resultTime/1048576);
        }
        System.out.println("CBC Decryption as:"+"./com/pratik/Data/AES_CBC_"+aesCBCKey.getEncoded().length*8+"_DEC-"+filename);
    }

    public static  void encrypt_AES_CTR(String filepath,Cipher instance,SecretKey aesKey,IvParameterSpec iv) throws IOException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        //File path
        String filename = filepath;
        long startTime=0,stopTime=0,resultTime=0;
        String outputPath = "./com/pratik/Data/AES_CTR_"+aesKey.getEncoded().length*8+"_EN-"+filepath;

        filepath = "./com/pratik/Data/"+filepath;
        int looptime = 5;
        if(filename.equals("file-small.bin")){
            looptime = 10000;
        }
        for (int i =0;i<looptime;i++){
            OutputStream outputstream = new FileOutputStream(outputPath);
            InputStream inputstream = new FileInputStream(filepath);
            byte[] data      = new byte[16];
            int bytesRead = inputstream.read(data,0,16);
            // Init the algorithm
            instance.init(Cipher.ENCRYPT_MODE, aesKey,iv);
            // First Encryption

            startTime =System.nanoTime();
            byte[] result = instance.update(data);
            outputstream.write(result);

            while(bytesRead != -1){
                bytesRead = inputstream.read(data,0,16);
                //System.out.println(inputstream.available());
                if(bytesRead != -1){
                    if(inputstream.available() > 0){
                        result = instance.update(data);
                    }else if(inputstream.available() == 0){
                        result = instance.doFinal(data);
                    }
                    outputstream.write(result);
                    stopTime = System.nanoTime();
                }
            }

            // File Handling maintenance
            outputstream.flush();
            outputstream.close();
            inputstream.close();
        }
        resultTime= stopTime-startTime;
        System.out.println("Time Taken is:"+resultTime);
        if(filename.equals("file-small.bin")){
            System.out.println("Speed Per Byte(nanoseconds/Byte):"+resultTime/1024);
        }else if(filename.equals("file-large.bin")){
            System.out.println("Speed Per Byte(nanoseconds/Byte):"+resultTime/1048576);
        }
        System.out.println("CTR Encryption as:"+outputPath);
    }

    public static void decrypt_AES_CTR(String filepath,Cipher instance,SecretKey aesKey,IvParameterSpec iv) throws IOException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException{
        String filename = filepath;
        long startTime=0,stopTime=0,resultTime=0;
        String in = "./com/pratik/Data/AES_CTR_"+aesKey.getEncoded().length*8+"_EN-"+filepath;
        String out = "./com/pratik/Data/AES_CTR_"+aesKey.getEncoded().length*8+"_DEC-"+filepath;
        int looptime = 5;
        if(filename.equals("file-small.bin")){
            looptime = 10000;
        }
        for (int i =0;i<looptime;i++){
            InputStream DECinputstream = new FileInputStream(in);
            OutputStream DECoutputstream = new FileOutputStream(out);
            //int size = DECinputstream.available();
            //System.out.println(size);
            byte[] data      = new byte[16];
            int bytesRead = DECinputstream.read(data,0,16);

            // Init the algorithm
            instance.init(Cipher.DECRYPT_MODE, aesKey,iv);

            // First Encryption

            startTime =System.nanoTime();
            byte[] result = instance.update(data);
            DECoutputstream.write(result);

            while(bytesRead != -1){
                bytesRead = DECinputstream.read(data,0,16);
                //System.out.println(DECinputstream.available());
                if(bytesRead != -1){
                    if(DECinputstream.available() > 0){
                        result = instance.update(data);
                    }else if(DECinputstream.available() == 0){
                        //System.out.println("final");
                        result = instance.doFinal(data);
                    }
                    DECoutputstream.write(result);
                    stopTime = System.nanoTime();
                }
            }

            // File Handling maintenance
            DECoutputstream.flush();
            DECoutputstream.close();
            DECinputstream.close();
        }
        resultTime= stopTime-startTime;
        System.out.println("Time Taken is:"+resultTime);
        if(filename.equals("file-small.bin")){
            System.out.println("Speed Per Byte(nanoseconds/Byte):"+resultTime/1024);
        }else if(filename.equals("file-large.bin")){
            System.out.println("Speed Per Byte(nanoseconds/Byte):"+resultTime/1048576);
        }
        System.out.println("CTR Decryption as:"+"./com/pratik/Data/AES_CTR_"+aesKey.getEncoded().length*8+"_DEC-file-small.bin");
    }

    public static void printHex(byte[] input){
        System.out.println();
        for(int i =0;i<input.length;i++){
            if(Integer.toHexString(input[i] & 0xFF).length() == 1){
                System.out.print("0"+Integer.toHexString((input[i] & 0xFF)));
            }else
                System.out.print(Integer.toHexString(input[i] & 0xFF));
        }
    }

    public static byte[] hash_256(String filepath) throws NoSuchAlgorithmException, IOException {
        //File path
        String filename = filepath;
        long startTime=0,stopTime=0,resultTime=0;
        filepath = "./com/pratik/Data/"+filepath;
        byte[] result = null;
        int looptime = 5;
        if(filename.equals("file-small.bin")){
            looptime = 10000;
        }
        for(int i = 0;i<looptime;i++){
            InputStream inputstream = new FileInputStream(filepath);

            MessageDigest messeagedigest = MessageDigest.getInstance("SHA-256");

            byte[] data      = new byte[64];

            startTime =System.nanoTime();
            int bytesRead = inputstream.read(data,0,64);
            // First Encryption
            messeagedigest.update(data);
            //outputstream.write(result);

            while(bytesRead != -1){
                bytesRead = inputstream.read(data,0,64);
                //System.out.println(inputstream.available());
                if(bytesRead != -1){
                    if(inputstream.available() > 0){
                        messeagedigest.update(data);
                    }else if(inputstream.available() == 0){
                        messeagedigest.update(data);
                    }
                }
            }
            result = messeagedigest.digest();
            stopTime = System.nanoTime();
            // File Handling maintenance
            inputstream.close();
        }
        resultTime= stopTime-startTime;
        System.out.println("Time Taken is:"+resultTime);
        if(filename.equals("file-small.bin")){
            System.out.println("Speed Per Byte(nanoseconds/Byte):"+resultTime/1024);
        }else if(filename.equals("file-large.bin")){
            System.out.println("Speed Per Byte(nanoseconds/Byte):"+resultTime/1048576);
        }
        return result;
    }

    public static byte[] hash_512(String filepath) throws NoSuchAlgorithmException, IOException {
        //File path
        String filename = filepath;
        byte[] result = null;
        long startTime=0,stopTime=0,resultTime=0;
        filepath = "./com/pratik/Data/"+filepath;

        int looptime = 5;
        if(filename.equals("file-small.bin")){
            looptime = 10000;
        }
        for(int i = 0;i<looptime;i++){
            InputStream inputstream = new FileInputStream(filepath);
            MessageDigest messeagedigest = MessageDigest.getInstance("SHA-512");

            byte[] data      = new byte[128];
            int bytesRead = inputstream.read(data,0,128);
            // First Encryption

            startTime =System.nanoTime();
            messeagedigest.update(data);
            //outputstream.write(result);

            while(bytesRead != -1){
                bytesRead = inputstream.read(data,0,128);
                //System.out.println(inputstream.available());
                if(bytesRead != -1){
                    if(inputstream.available() > 0){
                        messeagedigest.update(data);
                    }else if(inputstream.available() == 0){
                        messeagedigest.update(data);
                    }
                }
            }
            result = messeagedigest.digest();
            stopTime = System.nanoTime();

            // File Handling maintenance
            inputstream.close();
        }
        resultTime= stopTime-startTime;
        System.out.println("Time Taken is:"+resultTime);
        if(filename.equals("file-small.bin")){
            System.out.println("Speed Per Byte(nanoseconds/Byte):"+resultTime/1024);
        }else if(filename.equals("file-large.bin")){
            System.out.println("Speed Per Byte(nanoseconds/Byte):"+resultTime/1048576);
        }
        return result;
    }

    public static byte[] hash_sha3256(String filepath) throws IOException {
        //File path
        String filename = filepath;
        long startTime=0,stopTime=0,resultTime=0;
        filepath = "./com/pratik/Data/"+filepath;

        byte[] result = null;
        int looptime = 5;
        if(filename.equals("file-small.bin")){
            looptime = 10000;
        }
        for(int i =0;i<looptime;i++){
            InputStream inputstream = new FileInputStream(filepath);
            SHA3.DigestSHA3 messagedigest = new SHA3.Digest256();
            byte[] data      = new byte[136];

            startTime =System.nanoTime();
            int bytesRead = inputstream.read(data,0,136);
            // First Encryption

            messagedigest.update(data);
            //outputstream.write(result);
            while(bytesRead != -1){
                //System.out.println(inputstream.available());
                if(bytesRead != -1){
                    if(inputstream.available() > 136){
                        bytesRead = inputstream.read(data,0,136);
                        messagedigest.update(data);
                    }else{
                        byte[] lastData = new byte[inputstream.available()];
                        bytesRead = inputstream.read(lastData);
                        messagedigest.update(lastData);
                        bytesRead = -1;
                    }
                }
            }
            //System.out.println();
            //printHex(data);
            result = messagedigest.digest();
            stopTime = System.nanoTime();
            // File Handling maintenance
            inputstream.close();
        }
        resultTime= stopTime-startTime;
        System.out.println("Time Taken is:"+resultTime);
        if(filename.equals("file-small.bin")){
            System.out.println("Speed Per Byte(nanoseconds/Byte):"+resultTime/1024);
        }else if(filename.equals("file-large.bin")){
            System.out.println("Speed Per Byte(nanoseconds/Byte):"+resultTime/1048576);
        }
        return result;

    }

    public static void encrypt_rsa(String filepath,Cipher rsa,RSAPublicKey publicKey,int keySize) throws IOException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        //File path
        String filename = filepath;
        String outputPath = "./com/pratik/Data/RSA_EN_"+keySize+"-"+filepath;
        OutputStream outputstream = new FileOutputStream(outputPath);
        filepath = "./com/pratik/Data/"+filepath;
        InputStream inputstream = new FileInputStream(filepath);
        //int size = inputstream.available();
        //System.out.println(size);
        byte[] data      = new byte[128];
        int bytesRead = inputstream.read(data,0,128);
        // Init the algorithm

        rsa.init(Cipher.ENCRYPT_MODE,publicKey);

        // First Encryption
        long startTime=0,stopTime=0,resultTime=0;
        startTime =System.nanoTime();
        byte[] result = rsa.doFinal(data);
        outputstream.write(result);

        while(bytesRead != -1){
            //System.out.println(DECinputstream.available());
            if(bytesRead != -1){
                if(inputstream.available() > 128){
                    bytesRead = inputstream.read(data,0,128);
                    result = rsa.doFinal(data);
                }else{
                    byte[] lastData = new byte[inputstream.available()];
                    bytesRead = inputstream.read(lastData);
                    result = rsa.doFinal(lastData);
                    bytesRead = -1;
                }
                outputstream.write(result);
                stopTime = System.nanoTime();
                //System.out.println("Result:"+result.length);
            }
        }
        // File Handling maintenance
        outputstream.flush();
        outputstream.close();
        outputstream.close();
        resultTime= stopTime-startTime;
        System.out.println("Time Taken is:"+resultTime);
        if(filename.equals("file-small.bin")){
            System.out.println("Speed Per Byte(nanoseconds/Byte):"+resultTime/1024);
        }else if(filename.equals("file-large.bin")){
            System.out.println("Speed Per Byte(nanoseconds/Byte):"+resultTime/1048576);
        }
        System.out.println("Encrypted as:"+outputPath);
    }

    public static void decrypt_rsa(String filepath,Cipher rsa,RSAPrivateKey privateKey,int keySize) throws InvalidKeyException, IOException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchAlgorithmException {
        // Solving Error of Padding:https://stackoverflow.com/questions/32161720/breaking-down-rsa-ecb-oaepwithsha-256andmgf1padding
        //File path
        String filename = filepath;
        String inpath = "./com/pratik/Data/RSA_EN_"+keySize+"-"+filepath;
        InputStream inputstream = new FileInputStream(inpath);
        filepath = "./com/pratik/Data/RSA_DEC_"+keySize+"-"+filepath;
        OutputStream outputstream = new FileOutputStream(filepath);
        int blockSize = 1;
        if (keySize == 2048){
            blockSize= 2048/8;
        }else if(keySize == 3072){
            blockSize = 3072/8;
        }
        //int size = inputstream.available();
        //System.out.println(size);
        byte[] data      = new byte[blockSize];
        int bytesRead = inputstream.read(data,0,blockSize);
        // Init the algorithm
        //Cipher oaepFromInit = Cipher.getInstance("RSA/ECB/OAEPPadding");
        //OAEPParameterSpec oaepParams = new OAEPParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-1"), PSource.PSpecified.DEFAULT);
        rsa.init(Cipher.DECRYPT_MODE, privateKey);
        //System.out.println("Length"+data.length);
        // First Encryption
        long startTime=0,stopTime=0,resultTime=0;
        startTime =System.nanoTime();
        byte[] result = rsa.doFinal(data);
        outputstream.write(result);

        while(bytesRead != -1){
            //System.out.println(inputstream.available());
            if(bytesRead != -1){
                if(inputstream.available() > blockSize){
                    bytesRead = inputstream.read(data,0,blockSize);
                    result = rsa.doFinal(data);
                }else{
                    byte[] lastData = new byte[inputstream.available()];
                    bytesRead = inputstream.read(lastData);
                    result = rsa.doFinal(lastData);
                    bytesRead = -1;
                }
                outputstream.write(result);
                stopTime = System.nanoTime();
            }
        }
        // File Handling maintenance
        outputstream.flush();
        outputstream.close();
        outputstream.close();
        resultTime= stopTime-startTime;
        System.out.println("Time Taken is:"+resultTime);
        if(filename.equals("file-small.bin")){
            System.out.println("Speed Per Byte(nanoseconds/Byte):"+resultTime/1024);
        }else if(filename.equals("file-large.bin")){
            System.out.println("Speed Per Byte(nanoseconds/Byte):"+resultTime/1048576);
        }
        System.out.println("Decrypted as:"+filepath);
    }

    public static byte[] dsa_sign(String filepath, Signature dsa, DSAPrivateKey privateKey,SecureRandom secureRandom) throws InvalidKeyException, IOException, SignatureException {
        String filename = filepath;
        long startTime=0,stopTime=0,resultTime=0;
        byte[] result = null;
        int bytesRead=0;
        filepath = "./com/pratik/Data/"+filepath;
        //int size = inputstream.available();
        int looptime = 5;
        if(filename.equals("file-small.bin")){
            looptime = 5;
        }

        for(int i = 0;i<looptime;i++){
            InputStream inputstream = new FileInputStream(filepath);
            dsa.initSign(privateKey,secureRandom);
            //System.out.println(inputstream.available());
            byte[] data      = new byte[64];
            bytesRead = inputstream.read(data,0,64);
            startTime = System.nanoTime();
            dsa.update(data);

            while(bytesRead != -1){
                //System.out.println(inputstream.available());
                if(bytesRead != -1){
                    if(inputstream.available() > 64){
                        bytesRead = inputstream.read(data,0,64);
                        dsa.update(data);
                    }else {
                        byte[] lastData = new byte[inputstream.available()];
                        bytesRead = inputstream.read(lastData);
                        dsa.update(lastData);
                        bytesRead = -1;
                    }
                }
            }
            result = dsa.sign();
            stopTime = System.nanoTime();
            // File Handling maintenance
            inputstream.close();
        }
        resultTime= stopTime-startTime;
        System.out.println("Time Taken is:"+resultTime);
        if(filename.equals("file-small.bin")){
            System.out.println("Speed Per Byte(nanoseconds/Byte):"+resultTime/1024);
        }else if(filename.equals("file-large.bin")){
            System.out.println("Speed Per Byte(nanoseconds/Byte):"+resultTime/1048576);
        }
        return result;
    }

    public static boolean dsa_verify(String filepath,byte[] digitalSignature,Signature dsa,DSAPublicKey publicKey) throws InvalidKeyException, SignatureException, IOException {
        String filename = filepath;
        long startTime=0,stopTime=0,resultTime=0;
        filepath = "./com/pratik/Data/"+filepath;

        int looptime = 5;
        if(filename.equals("file-small.bin")){
            looptime = 5;
        }
        for(int i = 0; i<looptime;i++){
            startTime =System.nanoTime();
            InputStream inputstream = new FileInputStream(filepath);
            dsa.initVerify(publicKey);

            byte[] data      = new byte[inputstream.available()];
            inputstream.read(data,0,inputstream.available());
            dsa.update(data);
            stopTime = System.nanoTime();

        }
        resultTime= stopTime-startTime;
        System.out.println("Time Taken is:"+resultTime);
        if(filename.equals("file-small.bin")){
            System.out.println("Speed Per Byte(nanoseconds/Byte):"+resultTime/1024);
        }else if(filename.equals("file-large.bin")){
            System.out.println("Speed Per Byte(nanoseconds/Byte):"+resultTime/1048576);
        }
        return dsa.verify(digitalSignature);
    }
}
