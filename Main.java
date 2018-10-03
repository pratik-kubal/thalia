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
        SecretKey aes128 = genAES128(128);
        IvParameterSpec iv = genIV(aesCBC);
        // Encrypt file
        encrypt_AES_CBC("file-small.bin",aesCBC,aes128,iv);
        encrypt_AES_CBC("file-large.bin",aesCBC,aes128,iv);
        // Decrypt File
        decrypt_AES_CBC("file-small.bin",aesCBC,aes128,iv);
        decrypt_AES_CBC("file-large.bin",aesCBC,aes128,iv);

    // Q1.b
        System.out.println("Q1.b");
        // Make Instance of the algorithm
        Cipher aesCTR = Cipher. getInstance("AES/CTR/NoPadding");
        // Generate Key
        IvParameterSpec ctrIv = genIV(aesCBC);
        // Encrypt file
        encrypt_AES_CTR("file-small.bin",aesCTR,aes128,ctrIv);
        encrypt_AES_CTR("file-large.bin",aesCTR,aes128,ctrIv);
        // Decrypt File
        decrypt_AES_CTR("file-small.bin",aesCTR,aes128,ctrIv);
        decrypt_AES_CTR("file-large.bin",aesCTR,aes128,ctrIv);
    // Q1.c
        System.out.println("Q1.c");
        // Generating 256-bit key
        SecretKey aes256 = genAES128(256);
        // Encrypt file
        encrypt_AES_CTR("file-small.bin",aesCTR,aes256,ctrIv);
        encrypt_AES_CTR("file-large.bin",aesCTR,aes256,ctrIv);
        // Decrypt File
        decrypt_AES_CTR("file-small.bin",aesCTR,aes256,ctrIv);
        decrypt_AES_CTR("file-large.bin",aesCTR,aes256,ctrIv);
    // Q1.d
        System.out.println("Q1.d");
        System.out.print("SHA256: ");
        System.out.println("Small File");
        printHex(hash_256("file-small.bin"));
        System.out.println("Large File");
        printHex(hash_256("file-large.bin"));
        System.out.println();
        System.out.print("SHA512: ");
        System.out.println("Small File");
        printHex(hash_512("file-small.bin"));
        System.out.println("Large File");
        printHex(hash_512("file-large.bin"));
        System.out.println();
        System.out.print("SHA3-256: ");
        System.out.println("Small File");
        printHex(hash_sha3256("file-small.bin"));
        System.out.println("Large File");
        printHex(hash_sha3256("file-large.bin"));
        System.out.println();
	// Q1.e
        System.out.println("Q1.e");
        KeyPair rsakeyPair = genSymmetricKey(2048,"RSA");
        RSAPublicKey rsapublicKey = (RSAPublicKey) rsakeyPair.getPublic();
        RSAPrivateKey rsaprivateKey = (RSAPrivateKey) rsakeyPair.getPrivate();

        Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");

        encrypt_rsa("file-small.bin",rsa,rsapublicKey,2048);
        decrypt_rsa("file-small.bin",rsa,rsaprivateKey,2048);
        encrypt_rsa("file-large.bin",rsa,rsapublicKey,2048);
        decrypt_rsa("file-large.bin",rsa,rsaprivateKey,2048);
    // Q1.f
        System.out.println("Q1.f");
        rsakeyPair = genSymmetricKey(3072,"RSA");
        rsapublicKey = (RSAPublicKey) rsakeyPair.getPublic();
        rsaprivateKey = (RSAPrivateKey) rsakeyPair.getPrivate();

        encrypt_rsa("file-small.bin",rsa,rsapublicKey,3072);
        decrypt_rsa("file-small.bin",rsa,rsaprivateKey,3072);
        encrypt_rsa("file-large.bin",rsa,rsapublicKey,3072);
        decrypt_rsa("file-large.bin",rsa,rsaprivateKey,3072);
	// Q1.g
        System.out.println("Q1.g");
        KeyPair dsakeyPair = genSymmetricKey(2048,"DSA");
        DSAPublicKey dsapublicKey = (DSAPublicKey) dsakeyPair.getPublic();
        DSAPrivateKey dsaprivateKey = (DSAPrivateKey) dsakeyPair.getPrivate();
        Signature dsa = Signature.getInstance("SHA256WithDSA");
        SecureRandom secureRandom2048 = new SecureRandom();
        System.out.println("Digital Signature of small file:");
        byte[] dsa_byte = dsa_sign("file-small.bin",dsa,dsaprivateKey,secureRandom2048);
        printHex(dsa_byte);
        System.out.println();
        System.out.println("Digital Signature verification:");
        System.out.println(dsa_verify("file-small.bin",dsa_byte,dsa,dsapublicKey));

        System.out.println("Digital Signature of large file:");
        dsa_byte = dsa_sign("file-large.bin",dsa,dsaprivateKey,secureRandom2048);
        printHex(dsa_byte);
        System.out.println();
        System.out.println("Digital Signature verification:");
        System.out.println(dsa_verify("file-large.bin",dsa_byte,dsa,dsapublicKey));

        System.out.println("Opposite Files verification check:");
        System.out.println(dsa_verify("file-small.bin",dsa_byte,dsa,dsapublicKey));
    // Q1.h
        System.out.println("Q1.h");
        dsakeyPair = genSymmetricKey(3072,"DSA");
        dsapublicKey = (DSAPublicKey) dsakeyPair.getPublic();
        dsaprivateKey = (DSAPrivateKey) dsakeyPair.getPrivate();

        SecureRandom secureRandom3072 = new SecureRandom();
        System.out.println("Digital Signature of small file:");
        dsa_byte = dsa_sign("file-small.bin",dsa,dsaprivateKey,secureRandom3072);
        printHex(dsa_byte);
        System.out.println();
        System.out.println("Digital Signature verification:");
        System.out.println(dsa_verify("file-small.bin",dsa_byte,dsa,dsapublicKey));

        System.out.println("Digital Signature of large file:");
        dsa_byte = dsa_sign("file-large.bin",dsa,dsaprivateKey,secureRandom3072);
        printHex(dsa_byte);
        System.out.println();
        System.out.println("Digital Signature verification:");
        System.out.println(dsa_verify("file-large.bin",dsa_byte,dsa,dsapublicKey));

        System.out.println("Opposite Files verification check:");
        System.out.println(dsa_verify("file-small.bin",dsa_byte,dsa,dsapublicKey));

    }

    public static SecretKey genAES128(int keySize) throws  NoSuchAlgorithmException{
        KeyGenerator aesCBCKeyInstance = KeyGenerator.getInstance("AES");
        SecureRandom random_key = new SecureRandom();
        aesCBCKeyInstance.init(keySize,random_key);
        SecretKey aesCBCKey = aesCBCKeyInstance.generateKey();

        return aesCBCKey;

    }

    public static KeyPair genSymmetricKey(int keySize,String scheme) throws NoSuchAlgorithmException {
        KeyPairGenerator key = KeyPairGenerator.getInstance(scheme);
        SecureRandom random_key = new SecureRandom();
        key.initialize(keySize,random_key);
        KeyPair keyPair = key.generateKeyPair();
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
        Cipher aesCBC = instance;
        IvParameterSpec ivspec = iv;
        String outputPath = "src/com/pratik/Data/AES_CBC_"+aesCBCKey.getEncoded().length*8+"_EN-"+filepath;
        OutputStream outputstream = new FileOutputStream(outputPath);
        filepath = "src/com/pratik/Data/"+filepath;
        InputStream inputstream = new FileInputStream(filepath);
        int size = inputstream.available();

        byte[] data      = new byte[16];
        int bytesRead = inputstream.read(data,0,16);
        //int i = 1;


        // Init the algorithm
        aesCBC.init(Cipher.ENCRYPT_MODE, aesCBCKey,ivspec);
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
        }

        // File Handling maintenance
        outputstream.flush();
        outputstream.close();
        inputstream.close();
        System.out.println("CBC Encryption as:"+outputPath);
    }

    public static void decrypt_AES_CBC(String filename,Cipher instance,SecretKey aesCBCKey,IvParameterSpec iv)  throws InvalidKeyException, IOException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        Cipher aesCBC = instance;
        IvParameterSpec ivspec = iv;
        InputStream DECinputstream = new FileInputStream("src/com/pratik/Data/AES_CBC_"+aesCBCKey.getEncoded().length*8+"_EN-"+filename);
        OutputStream DECoutputstream = new FileOutputStream("src/com/pratik/Data/AES_CBC_"+aesCBCKey.getEncoded().length*8+"_DEC-"+filename);

        int size = DECinputstream.available();
        //System.out.println(size);
        byte[] data      = new byte[16];
        int bytesRead = DECinputstream.read(data,0,16);
        aesCBC.init(Cipher.DECRYPT_MODE, aesCBCKey,ivspec);

        // First Encryption
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
            }
        }
        // File Handling maintenance
        DECoutputstream.flush();
        DECoutputstream.close();
        DECinputstream.close();

        System.out.println("CBC Decryption as:"+"src/com/pratik/Data/AES_CBC_"+aesCBCKey.getEncoded().length*8+"_DEC-"+filename);
    }

    public static  void encrypt_AES_CTR(String filepath,Cipher instance,SecretKey aesKey,IvParameterSpec iv) throws IOException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        //File path
        String outputPath = "src/com/pratik/Data/AES_CTR_"+aesKey.getEncoded().length*8+"_EN-"+filepath;
        OutputStream outputstream = new FileOutputStream(outputPath);
        filepath = "src/com/pratik/Data/"+filepath;
        InputStream inputstream = new FileInputStream(filepath);
        int size = inputstream.available();

        byte[] data      = new byte[16];
        int bytesRead = inputstream.read(data,0,16);
        // Init the algorithm
        instance.init(Cipher.ENCRYPT_MODE, aesKey,iv);
        // First Encryption
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
            }
        }
        // File Handling maintenance
        outputstream.flush();
        outputstream.close();
        inputstream.close();

        System.out.println("CTR Encryption as:"+outputPath);
    }

    public static void decrypt_AES_CTR(String filepath,Cipher instance,SecretKey aesKey,IvParameterSpec iv) throws IOException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException{
        InputStream DECinputstream = new FileInputStream("src/com/pratik/Data/AES_CTR_"+aesKey.getEncoded().length*8+"_EN-"+filepath);
        OutputStream DECoutputstream = new FileOutputStream("src/com/pratik/Data/AES_CTR_"+aesKey.getEncoded().length*8+"_DEC-"+filepath);

        //int size = DECinputstream.available();
        //System.out.println(size);
        byte[] data      = new byte[16];
        int bytesRead = DECinputstream.read(data,0,16);

        // Init the algorithm
        instance.init(Cipher.DECRYPT_MODE, aesKey,iv);

        // First Encryption
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
            }
        }
        // File Handling maintenance
        DECoutputstream.flush();
        DECoutputstream.close();
        DECinputstream.close();
        System.out.println("CTR Decryption as:"+"src/com/pratik/Data/AES_CTR_"+aesKey.getEncoded().length*8+"_DEC-file-small.bin");
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
        filepath = "src/com/pratik/Data/"+filepath;
        InputStream inputstream = new FileInputStream(filepath);

        MessageDigest messeagedigest = MessageDigest.getInstance("SHA-256");

        byte[] data      = new byte[64];
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
        byte[] result = messeagedigest.digest();
        // File Handling maintenance
        inputstream.close();
        return result;
    }

    public static byte[] hash_512(String filepath) throws NoSuchAlgorithmException, IOException {
        //File path
        filepath = "src/com/pratik/Data/"+filepath;
        InputStream inputstream = new FileInputStream(filepath);

        MessageDigest messeagedigest = MessageDigest.getInstance("SHA-512");

        byte[] data      = new byte[128];
        int bytesRead = inputstream.read(data,0,128);
        // First Encryption
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
        byte[] result = messeagedigest.digest();
        // File Handling maintenance
        inputstream.close();
        return result;
    }

    public static byte[] hash_sha3256(String filepath) throws IOException {
        //File path
        filepath = "src/com/pratik/Data/"+filepath;
        InputStream inputstream = new FileInputStream(filepath);
        int size = inputstream.available();
        SHA3.DigestSHA3 messagedigest = new SHA3.Digest256();
        byte[] data      = new byte[136];
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
        byte[] result = messagedigest.digest();
        // File Handling maintenance
        inputstream.close();
        return result;

    }

    public static void encrypt_rsa(String filepath,Cipher rsa,RSAPublicKey publicKey,int keySize) throws IOException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        //File path
        String outputPath = "src/com/pratik/Data/RSA_EN_"+keySize+"-"+filepath;
        OutputStream outputstream = new FileOutputStream(outputPath);
        filepath = "src/com/pratik/Data/"+filepath;
        InputStream inputstream = new FileInputStream(filepath);
        //int size = inputstream.available();
        //System.out.println(size);
        byte[] data      = new byte[128];
        int bytesRead = inputstream.read(data,0,128);
        // Init the algorithm

        rsa.init(Cipher.ENCRYPT_MODE,publicKey);

        // First Encryption
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
                //System.out.println("Result:"+result.length);
            }
        }
        // File Handling maintenance
        outputstream.flush();
        outputstream.close();
        outputstream.close();

        System.out.println("Encrypted as:"+outputPath);
    }

    public static void decrypt_rsa(String filepath,Cipher rsa,RSAPrivateKey privateKey,int keySize) throws InvalidKeyException, IOException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchAlgorithmException {
        // Solving Error of Padding:https://stackoverflow.com/questions/32161720/breaking-down-rsa-ecb-oaepwithsha-256andmgf1padding
        //File path
        String inpath = "src/com/pratik/Data/RSA_EN_"+keySize+"-"+filepath;
        InputStream inputstream = new FileInputStream(inpath);
        filepath = "src/com/pratik/Data/RSA_DEC_"+keySize+"-"+filepath;
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
            }
        }
        // File Handling maintenance
        outputstream.flush();
        outputstream.close();
        outputstream.close();

        System.out.println("Decrypted as:"+filepath);
    }

    public static byte[] dsa_sign(String filepath, Signature dsa, DSAPrivateKey privateKey,SecureRandom secureRandom) throws InvalidKeyException, IOException, SignatureException {
        filepath = "src/com/pratik/Data/"+filepath;
        InputStream inputstream = new FileInputStream(filepath);
        //int size = inputstream.available();

        dsa.initSign(privateKey,secureRandom);

        byte[] data      = new byte[inputstream.available()];

        dsa.update(data);

        byte[] result = dsa.sign();

        // File Handling maintenance
        inputstream.close();
        return result;
    }

    public static boolean dsa_verify(String filepath,byte[] digitalSignature,Signature dsa,DSAPublicKey publicKey) throws InvalidKeyException, SignatureException, IOException {
        filepath = "src/com/pratik/Data/"+filepath;
        InputStream inputstream = new FileInputStream(filepath);

        dsa.initVerify(publicKey);

        byte[] data      = new byte[inputstream.available()];

        dsa.update(data);

        return dsa.verify(digitalSignature);
    }
}
