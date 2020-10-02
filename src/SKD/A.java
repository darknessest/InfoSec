package SKD;

import java.nio.charset.StandardCharsets;
import java.net.*;
import java.io.*;

import static SKD.crypto.*;

/**
 * 1. Create a socket connection to machine B
 * 2. Generate a session key
 * 3. Send a session key encrypted with master_key
 * 4. Send a message encrypted with a session key
 */

public class A {

    private static final String master_key = "2ae164ad";   // shared key
    private static String session_key = "";

    private static Socket socket = null;
    private static DataInputStream input = null;
    private static DataOutputStream out = null;
    private static String address = "127.0.0.1";
    private static int port = 5555;


    public void startConv() {
        // 1. Create a socket to machine B

        // 2. Generate a session key
        session_key = genKey();
        // 3. Encrypt session key with master key
        byte[] enc_msg = Encrypt(master_key, session_key);
        // 4. Send encrypted session key

        // 5. Send a message(s) encrypted with a session key


    }

    // Test
    public static void main(String[] args) {
        session_key = genKey();
        String msg = session_key;
        System.out.println("original message: " + msg);

        byte[] enc_msg = Encrypt(master_key, msg);
        System.out.println("encrypted message: " + org.bouncycastle.util.encoders.Hex.toHexString(enc_msg));

        byte[] dec_msg = Decrypt(master_key, enc_msg);
        String dec_message = new String(dec_msg, StandardCharsets.UTF_8)
                .replaceAll(String.valueOf((char) 0), ""); // some trailing NULLS mb present
        System.out.println("rcvd decrypted message: " + dec_message);

        msg = "Test Message Hello, trying to send a lot of text here";
        System.out.println("\noriginal message: " + msg);
        enc_msg = Encrypt(session_key, msg);
        System.out.println("new encrypted message: " + org.bouncycastle.util.encoders.Hex.toHexString(enc_msg));
        dec_msg = Decrypt(session_key, enc_msg);
        dec_message = new String(dec_msg, StandardCharsets.UTF_8)
                .replaceAll(String.valueOf((char) 0), ""); // some trailing NULLS mb present
        System.out.println("rcvd decrypted message: " + dec_message);

// establish a connection
    }

}
