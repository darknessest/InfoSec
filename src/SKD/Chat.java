package SKD;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

import static SKD.FileToSend.deserialize;
import static SKD.crypto.*;

public class Chat extends Thread {

    private static DataOutputStream out;
    private static DataInputStream in;
    private static Socket socket;
    private static BufferedReader brin;
    private final boolean isSender;
    private static boolean running = false;
    private final String exit_word = "exit()";
    private final String send_file_word = "send()";
    private final String send_file_error = "send_err()";

    private static final String master_key = "2ae164ad";   // shared key
    private static String session_key = "";

    public Chat(boolean isSender) {
        super();
        this.isSender = isSender;
    }

    private static void initServer(int port) {
        try {
            ServerSocket serverSocket = new ServerSocket(port);
            serverSocket.setSoTimeout(100000);  // 100 sec

            System.out.println("SYSTEM: waiting for client on port " +
                    serverSocket.getLocalPort() + "...");
            socket = serverSocket.accept();

            System.out.println("SYSTEM: just connected to " + socket.getRemoteSocketAddress());

            in = new DataInputStream(socket.getInputStream());
            out = new DataOutputStream(socket.getOutputStream());
            out.flush();

            // Encrypting connection
            System.out.println("SYSTEM: encrypting connection");
            session_key = genKey();

            System.out.println("SYSTEM: session key: " + session_key);

            byte[] enc_msg = Encrypt(master_key, session_key);
//            System.out.println("SYSTEM: encrypted message: " + org.bouncycastle.util.encoders.Hex.toHexString(enc_msg));

            out.writeUTF(org.bouncycastle.util.encoders.Hex.toHexString(enc_msg));

        } catch (SocketTimeoutException s) {
            System.out.println("SYSTEM: Socket timed out!");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void initClient(String serverName, int port) {
        try {
            System.out.println("SYSTEM: Connecting to " + serverName + " on port " + port);
            socket = new Socket(serverName, port);

            System.out.println("SYSTEM: Just connected to " + socket.getRemoteSocketAddress());

            out = new DataOutputStream(socket.getOutputStream());
            in = new DataInputStream(socket.getInputStream());

            // Encrypting connection
            System.out.println("SYSTEM: encrypting connection");
            String rcvd_msg = in.readUTF();
            System.out.println("SYSTEM: encrypted session key: " + rcvd_msg);

            byte[] dec_msg = Decrypt(master_key, org.bouncycastle.util.encoders.Hex.decodeStrict(rcvd_msg));
            String dec_message = new String(dec_msg, StandardCharsets.UTF_8)
                    .replaceAll(String.valueOf((char) 0), ""); // some trailing NULLS mb present

            session_key = dec_message;
            System.out.println("SYSTEM: decrypted session key: " + dec_message);

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void Send() {
        try {
            String toSend = brin.readLine();

            // Checking for special words
            if (toSend.equals(exit_word))
                running = false;
            if (toSend.equals(send_file_word)) {
                sendFile();
                return;
            }

            // Encrypting a message
            toSend = org.bouncycastle.util.encoders.Hex.toHexString(
                    Encrypt(session_key, toSend));

            // Sending the message
            out.writeUTF(toSend);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void Receive() {
        try {
            String toPrint = in.readUTF();
            System.out.println(">>> ENC: " + toPrint);

            // Decrypting a message
            toPrint = new String(Decrypt(session_key, toPrint), StandardCharsets.UTF_8)
                    .replaceAll(String.valueOf((char) 0), "");

            // Checking for special words
            if (toPrint.equals(exit_word)) {
                System.out.println("SYSTEM: other client left");
                running = false;
            }
            if (toPrint.equals(send_file_word)) {
                receiveFile();
                return;
            }

            // Printing the message
            System.out.println(">>> " + toPrint);
        } catch (EOFException x) {
            System.out.println("SYSTEM: connection stopped abruptly, shutting down");
            running = false;
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void sendFile() throws IOException {
        System.out.println("SYSTEM: please enter path to a file you want to send: ");
        String filename = brin.readLine();

        // sending file
        if (Files.exists(Paths.get(filename))) {
            FileToSend file = new FileToSend(filename, Files.readAllBytes(Paths.get(filename)));
            // notify about file sending
            out.writeUTF(org.bouncycastle.util.encoders.Hex.toHexString(
                    Encrypt(session_key, send_file_word)));

            // encrypting and sending
            out.write(Encrypt(session_key, file.serialize()));

            System.out.println("SYSTEM: file was sent");
        } else {
            // if file doesn't exist, stop sending
            System.out.println("SYSTEM: file doesn't exist, aborting ...");

            // TODO: check if useless
            out.writeUTF(org.bouncycastle.util.encoders.Hex.toHexString(
                    Encrypt(session_key,send_file_error)));
        }
    }

    private void receiveFile() throws IOException {
        System.out.println("SYSTEM: receiving file ...");

        // waiting for file to be sent
        // TODO: make more intelligent
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        // receiving file
        int count = in.available();
        byte[] file_bin = new byte[count];

        if (in.read(file_bin) == 0) {
            System.out.println("SYSTEM: file wasn't received. aborting ...");
            return;
        }

        // decrypting file
        FileToSend file = deserialize(Decrypt(session_key, file_bin));

        // saving file
        assert file != null;
        file.setName("_".concat(file.getName()));
        if (file.saveFile() == 0)
            System.out.println("SYSTEM: file received, and saved: " + file.getName());
        else
            System.out.println("SYSTEM: file wasn't saved");

        // comparing checksum
        String recalc_checksum = getFileCheckSum(file.getName());
        System.out.println("SYSTEM: sent file checksum:\t\t" + file.getChecksum());
        System.out.println("SYSTEM: received file checksum:\t" + recalc_checksum);

        assert recalc_checksum != null;
        if (recalc_checksum.equals(file.getChecksum()))
            System.out.println("SYSTEM: checksums are identical");
        else
            System.out.println("SYSTEM: checksums are different");
    }


    public void run() {
        while (running) {
            if (isSender) {
                Send();
            } else {
                Receive();
            }
            try {
                Thread.sleep(500); //milliseconds
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
        shutdown();
    }

    private void shutdown() {
        // TODO: make shutdown kill all threads
        System.out.println("SYSTEM: Shutting down chat...");
        try {
            out.close();
            in.close();
            brin.close();
            socket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    public static void main(String[] args) {
        System.out.println("1) To start a server");
        System.out.println("2) To start a client");

        brin = new BufferedReader(new InputStreamReader(System.in));
        int choice = 0;

        try {
            choice = Integer.parseInt(brin.readLine());
        } catch (IOException e) {
            e.printStackTrace();
        }

        switch (choice) {
            case 1:
                initServer(15555);
                break;
            case 2:
                initClient("127.0.0.1", 15555);
                break;
            default:
                System.out.println("SYSTEM: enter a valid number");
                break;
        }
        running = true;
        Thread send = new Chat(true);
        Thread rcvd = new Chat(false);

        send.start();
        rcvd.start();
    }
}
