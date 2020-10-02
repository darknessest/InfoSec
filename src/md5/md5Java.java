package md5;

import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;


public class md5Java {
    private static MessageDigest md;

    public static String getStringMd5(String input) {
        try {
            md = MessageDigest.getInstance("MD5");

            // digest() method is called to calculate message digest
            //  of an input digest() return array of byte
            byte[] messageDigest = md.digest(input.getBytes());

            StringBuilder hashtext = new StringBuilder();
            for (byte b : messageDigest) {
                hashtext.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
            }

            return hashtext.toString();
        }

        // For specifying wrong message digest algorithms
        catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static String getFileCheckSum(String filename)  {

        try {
            md = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        Path fileURI;

        try {
            fileURI = Paths.get(filename);
            md.update(Files.readAllBytes(fileURI));
            byte[] digest = md.digest();

            return DatatypeConverter.printHexBinary(digest);
        } catch (IOException e) {
            System.err.println("File doesn't exist or wrong path. Returning string's md5 hash ...");
            return getStringMd5(filename);
        }


    }
}