package SKD;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;

import javax.xml.bind.DatatypeConverter;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Arrays;


public class crypto {
    private static final int KEY_LENGTH_DES = 32;            // 8 byte for DES
    private static final int KEY_LENGTH_RSA = 1024;          // 1024 for RSA key pair
    private static String type;

    private static AsymmetricCipherKeyPair myKeyPair;
    private static RSAKeyParameters remotePublicKey;              // other party's public key
    private static AsymmetricBlockCipher RsaCipher;

    private static final byte[] master_key = "2ae164ad".getBytes();   // shared key
    private static byte[] session_key;


    public crypto(String algorithm) {
        type = algorithm.toUpperCase(); // rsa/des can be written in any case

        // pre-calculating key
        if (type.equals("RSA"))
            genRsaKey();
        else if (type.equals("DES"))
            genDesKey();
    }

    public void setRemotePublicKey(byte[] rpk) throws IOException {
        if (rpk.length > 1)
            remotePublicKey = deserializePubKey(rpk);
    }

    public byte[] Encrypt(String plain_text) {
        if (type.equals("RSA")) {
            System.out.println("SYSTEM: length to encrypt " + plain_text.length());
            return EncryptRsa(plain_text);
        } else if (type.equals("DES")) {
            return EncryptDes(session_key, plain_text);
        }
        return null;
    }

    public byte[] Encrypt(byte[] data) throws IOException {
        if (type.equals("RSA")) {
//            System.out.println("SYSTEM: length of binary to encrypt " + data.length);
            // checking for length constraint and splitting if needed
            // TODO: add calculation of the longest possible 'message'/chunksize
            if (data.length > 128) {
                int chunk_size = 128;
                int start = 0;
                byte[] temp;
                ByteArrayOutputStream bos = new ByteArrayOutputStream();

                for (int i = 0; i < data.length / (double) chunk_size; i++) {
                    temp = Arrays.copyOfRange(data, start, start + chunk_size);
//                    System.out.println("SYSTEM: length of temp binary to encrypt " + temp.length);
                    bos.write(EncryptRsa(temp));
                    start += chunk_size;
                }
                return bos.toByteArray();
            }

            return EncryptRsa(data);
        } else if (type.equals("DES")) {
            return EncryptDes(session_key, data);
        }
        return null;
    }

    public byte[] Decrypt(String plain_text) {
        if (type.equals("RSA")) {
            return DecryptRsa(plain_text);
        } else if (type.equals("DES")) {
            return DecryptDes(session_key, plain_text.getBytes());
        }
        return null;
    }

    public byte[] Decrypt(byte[] data) throws IOException {
        if (type.equals("RSA")) {
//            System.out.println("Decrypting length: " + data.length + " -- " + org.bouncycastle.util.encoders.Hex.toHexString(data));
            // with key size 1024, all messages has size 256
            // TODO: add calculation of the longest possible 'message'/chunksize
            if (data.length > 128) {

                int chunk_size = 128;
                int start = 0;
                byte[] temp;
                ByteArrayOutputStream bos = new ByteArrayOutputStream();

                for (int i = 0; i < data.length / (double) chunk_size; i++) {
                    temp = Arrays.copyOfRange(data, start, start + chunk_size);
//                    System.out.println("SYSTEM: length of temp binary to encrypt " + temp.length);
                    bos.write(Decrypt(temp));
                    start += chunk_size;
                }
                return bos.toByteArray();
            }
            return DecryptRsa(data);
        } else if (type.equals("DES")) {
            return DecryptDes(session_key, data);
        }
        return null;
    }

    private static byte[] EncryptDes(byte[] bin_key, String plain_text) {
//        byte[] bin_key = key.getBytes();
        byte[] ptBytes = plain_text.getBytes();
        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new DESEngine()));
        cipher.init(true, new KeyParameter(bin_key));
        byte[] rv = new byte[cipher.getOutputSize(ptBytes.length)];
        int tam = cipher.processBytes(ptBytes, 0, ptBytes.length, rv, 0);
        try {
            cipher.doFinal(rv, tam);
        } catch (Exception ce) {
            ce.printStackTrace();
        } finally {
            cipher.reset();
        }
        return rv;
    }

    private static byte[] EncryptDes(byte[] bin_key, byte[] plain_text) {
//        byte[] bin_key = key.getBytes();
        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new DESEngine()));
        cipher.init(true, new KeyParameter(bin_key));
        byte[] rv = new byte[cipher.getOutputSize(plain_text.length)];
        int tam = cipher.processBytes(plain_text, 0, plain_text.length, rv, 0);
        try {
            cipher.doFinal(rv, tam);
        } catch (Exception ce) {
            ce.printStackTrace();
        } finally {
            cipher.reset();
        }
        return rv;
    }

//    private static byte[] DecryptDes(byte[] bin_key, String cipherText) {
////        byte[] bin_key = key.getBytes();
//        byte[] cipherBytes = org.bouncycastle.util.encoders.Hex.decodeStrict(cipherText);
//        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new DESEngine()));
//        cipher.init(false, new KeyParameter(bin_key));
//        byte[] rv = new byte[cipher.getOutputSize(cipherBytes.length)];
//        int tam = cipher.processBytes(cipherBytes, 0, cipherBytes.length, rv, 0);
//        try {
//            cipher.doFinal(rv, tam);
//        } catch (Exception ce) {
//            ce.printStackTrace();
//        } finally {
//            cipher.reset();
//        }
//        return rv;
//    }

    private static byte[] DecryptDes(byte[] bin_key, byte[] cipherText) {
//        byte[] bin_key = key.getBytes();
        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new DESEngine()));
        cipher.init(false, new KeyParameter(bin_key));
        byte[] rv = new byte[cipher.getOutputSize(cipherText.length)];
        int tam = cipher.processBytes(cipherText, 0, cipherText.length, rv, 0);
        try {
            cipher.doFinal(rv, tam);
        } catch (Exception ce) {
            ce.printStackTrace();
        } finally {
            cipher.reset();
        }
        return rv;
    }

    public static byte[] EncryptRsa(String plain_text) {
        byte[] inputBytes = plain_text.getBytes();

        // Initializing the RSA object for Encryption with RSA public key. Remember, for encryption, public key is needed
        RsaCipher.init(true, (RSAKeyParameters) remotePublicKey);
        //Encrypting the input bytes
        byte[] cipheredBytes = new byte[0];
        try {
            cipheredBytes = RsaCipher.processBlock(inputBytes, 0, inputBytes.length);
        } catch (InvalidCipherTextException e) {
            e.printStackTrace();
        }

//        System.out.println("Encrypted data: \n" + org.bouncycastle.util.encoders.Hex.toHexString(cipheredBytes));
        return cipheredBytes;
    }

    public static byte[] EncryptRsa(byte[] plain_text) {
//        byte[] plain_text = plain_text.getBytes();

        // Initializing the RSA object for Encryption with RSA public key. Remember, for encryption, public key is needed
        AsymmetricBlockCipher cipher = new RSAEngine();

        // Initializing the RSA object for Encryption with RSA public key. Remember, for encryption, public key is needed
//        cipher.init(true, publicKey);
        RsaCipher.init(true, remotePublicKey);
        //Encrypting the input bytes
        byte[] cipheredBytes = new byte[0];
        try {
//            System.out.println("Encrypting length: " + org.bouncycastle.util.encoders.Hex.toHexString(plain_text));
            cipheredBytes = RsaCipher.processBlock(plain_text, 0, plain_text.length);
        } catch (InvalidCipherTextException e) {
            e.printStackTrace();
        }

//        System.out.println("Encrypted data: \n" + org.bouncycastle.util.encoders.Hex.toHexString(cipheredBytes));
        return cipheredBytes;
    }

    public static byte[] DecryptRsa(byte[] cipherText) {
        // Extracting the private key from the pair
        RsaCipher.init(false, myKeyPair.getPrivate());
        byte[] deciphered = new byte[0];
        try {
            deciphered = RsaCipher.processBlock(cipherText, 0, cipherText.length);
        } catch (InvalidCipherTextException e) {
            e.printStackTrace();
        }
//        System.out.println("Decrypted data: \n" + new String(deciphered, StandardCharsets.UTF_8));
        return deciphered;
    }

    public static byte[] DecryptRsa(String cipherText) {
        // Extracting the private key from the pair
        byte[] inputBytes = cipherText.getBytes();
        RsaCipher.init(false, myKeyPair.getPrivate());
        byte[] deciphered = new byte[0];
        try {
            deciphered = RsaCipher.processBlock(inputBytes, 0, cipherText.length());
        } catch (InvalidCipherTextException e) {
            e.printStackTrace();
        }
//        System.out.println("Decrypted data: \n" + new String(deciphered, StandardCharsets.UTF_8));
        return deciphered;
    }

    public static void genDesKey() {
        byte[] bin_key;
        CipherKeyGenerator cipherKeyGenerator = new CipherKeyGenerator();
        cipherKeyGenerator.init(new KeyGenerationParameters(new SecureRandom(), KEY_LENGTH_DES));
        // KEY_LENGTH specifies the size of key in bits i.e 8 bytes

        // key should be specifically 8 bytes long
        // but CipherKeyGenerator sometimes generates shorter keys
        while (true) {
            bin_key = cipherKeyGenerator.generateKey();
            BigInteger bigInteger = new BigInteger(bin_key).abs();
            if (bigInteger.bitLength() > KEY_LENGTH_DES - 4) {
                // TODO: check if can be casted straight to bytes
//                bigInteger.toByteArray();
                session_key = bigInteger.toString(16).getBytes();
                break;
            }
        }
    }

    private void genRsaKey() {
        RSAKeyPairGenerator rsaKeyPairGnr = new RSAKeyPairGenerator();
        try {
            rsaKeyPairGnr.init(new RSAKeyGenerationParameters(
                    RSAKeyGenParameterSpec.F4,  // 2^16+1
                    SecureRandom.getInstance("SHA1PRNG"),
                    KEY_LENGTH_RSA, // length: 1024, 2048, 4096
                    80   // probability of error 1 in 2^80
            ));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        myKeyPair = rsaKeyPairGnr.generateKeyPair();
    }

    public String getFileMd5(String filename) {
        MD5Digest md = new MD5Digest();
        try {
            byte[] bytes = Files.readAllBytes(Paths.get(filename));
            md.update(bytes, 0, bytes.length);
            byte[] md5Bytes = new byte[md.getDigestSize()];
            md.doFinal(md5Bytes, 0);
            org.bouncycastle.util.encoders.Hex.toHexString(md5Bytes);
            return DatatypeConverter.printHexBinary(md5Bytes);
        } catch (IOException e) {
            System.err.println("File doesn't exist or wrong path.");
            return null;
        }
    }

    public static String getBytesMd5(byte[] bytes) {
        MD5Digest md = new MD5Digest();
        md.update(bytes, 0, bytes.length);
        byte[] md5Bytes = new byte[md.getDigestSize()];
        md.doFinal(md5Bytes, 0);
        org.bouncycastle.util.encoders.Hex.toHexString(md5Bytes);
        return DatatypeConverter.printHexBinary(md5Bytes);
    }


    public byte[] keyExchange(boolean isServer, byte[] key) throws IOException {

        if (type.equals("RSA")) {

            RsaCipher = new RSAEngine();
            if (isServer) {
                // returning my public key
                System.out.println("server key pair" + Arrays.toString(serializePubKey(myKeyPair)));
                return serializePubKey(myKeyPair);
            } else {
                // saving remote public key
//                remotePublicKey = (RSAKeyParameters) Deserialize(key);
                System.out.println("client remote key " + Arrays.toString(key));
                remotePublicKey = deserializePubKey(key);

                // returning my public key
                System.out.println("client my key serialize " + Arrays.toString(serializePubKey(myKeyPair)));
                return serializePubKey(myKeyPair);
            }

        } else if (type.equals("DES")) {

            if (isServer) {
                // sending encrypted session key
                return EncryptDes(master_key, session_key);
            } else {
                // saving received encrypted session key
                session_key = trim(DecryptDes(master_key, key));
                System.out.println("session key in bin: " + Arrays.toString(session_key));
                System.out.println(new String(session_key, StandardCharsets.UTF_8));
            }

        } else {
            System.err.println(type + " is not a valid encryption");
        }

        return new byte[]{0};
    }

    private byte[] serializePubKey(AsymmetricCipherKeyPair obj) throws IOException {
        SubjectPublicKeyInfo pubKeyInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(obj.getPublic());
//        System.out.println("Serialize " + Arrays.toString(pubKeyInfo.toASN1Primitive().getEncoded()));
        return pubKeyInfo.toASN1Primitive().getEncoded();
    }

    private RSAKeyParameters deserializePubKey(byte[] bytes) throws IOException {
//        System.out.println("Deserialize " + Arrays.toString(bytes));
        return (RSAKeyParameters) PublicKeyFactory.createKey(bytes);
    }

    private byte[] trim(byte[] packet) {
        byte[] temp;
        int c = 0;
        for (byte x : packet)
            if (x != 0)
                c++;
        temp = new byte[c];
        if (c >= 0) System.arraycopy(packet, 0, temp, 0, c);
        return temp;
    }
}
