package SKD;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;

import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;

public class crypto {
    private static final int KEY_LENGTH = 32;          // 8 byte for DES

    public static byte[] Encrypt(String key, String plain_text) {
        byte[] bin_key = key.getBytes();
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

    public static byte[] Encrypt(String key, byte[] plain_text) {
        byte[] bin_key = key.getBytes();
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

    public static byte[] Decrypt(String key, String cipherText) {
        byte[] bin_key = key.getBytes();
        byte[] cipherBytes = org.bouncycastle.util.encoders.Hex.decodeStrict(cipherText);
        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new DESEngine()));
        cipher.init(false, new KeyParameter(bin_key));
        byte[] rv = new byte[cipher.getOutputSize(cipherBytes.length)];
        int tam = cipher.processBytes(cipherBytes, 0, cipherBytes.length, rv, 0);
        try {
            cipher.doFinal(rv, tam);
        } catch (Exception ce) {
            ce.printStackTrace();
        } finally {
            cipher.reset();
        }
        return rv;
    }

    public static byte[] Decrypt(String key, byte[] cipherText) {
        byte[] bin_key = key.getBytes();
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


    public static String genKey() {
        byte[] keyDES;
        CipherKeyGenerator cipherKeyGenerator = new CipherKeyGenerator();
        cipherKeyGenerator.init(new KeyGenerationParameters(new SecureRandom(), KEY_LENGTH));
        // KEY_LENGTH specifies the size of key in bits i.e 8 bytes

        // key should be specifically 8 bytes long
        // but CipherKeyGenerator sometimes generates shorter keys
        while (true) {
            keyDES = cipherKeyGenerator.generateKey();
            BigInteger bigInteger = new BigInteger(keyDES).abs();
            if (bigInteger.bitLength() > KEY_LENGTH - 4)
                return bigInteger.toString(16);
        }
    }

    public static String getFileCheckSum(String filename) {
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

    public static String getBytesCheckSum(byte[] bytes) {
        MD5Digest md = new MD5Digest();
        md.update(bytes, 0, bytes.length);
        byte[] md5Bytes = new byte[md.getDigestSize()];
        md.doFinal(md5Bytes, 0);
        org.bouncycastle.util.encoders.Hex.toHexString(md5Bytes);
        return DatatypeConverter.printHexBinary(md5Bytes);

    }
}