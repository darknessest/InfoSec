package md5;

import org.bouncycastle.crypto.digests.MD5Digest;

import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

public class md5BC {
    private static final MD5Digest md = new MD5Digest();

    public static String getStringMd5(String input) {
        md.update(input.getBytes(), 0, input.getBytes().length);
        byte[] md5Bytes = new byte[md.getDigestSize()];
        md.doFinal(md5Bytes, 0);
        // not available in some versions of bc
//        return org.bouncycastle.util.encoders.Hex.toHexString(md5Bytes);
        return DatatypeConverter.printHexBinary(md5Bytes);
    }

    public static String getFileCheckSum(String filename) {
        try {
            byte[] bytes = Files.readAllBytes(Paths.get(filename));
            md.update(bytes, 0, bytes.length);
            byte[] md5Bytes = new byte[md.getDigestSize()];
            md.doFinal(md5Bytes, 0);
            org.bouncycastle.util.encoders.Hex.toHexString(md5Bytes);
            return DatatypeConverter.printHexBinary(md5Bytes);
        } catch (IOException e) {
            System.err.println("File doesn't exist or wrong path. Returning string's md5 hash ...");
            return getStringMd5(filename);
        }
    }
}