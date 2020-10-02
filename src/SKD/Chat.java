package SKD;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

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
            if (toSend.equals(exit_word))
                running = false;
            if (toSend.equals(send_file_word)) {
                out.writeUTF(send_file_word);
                send_file();
            }
            toSend = org.bouncycastle.util.encoders.Hex.toHexString(
                    Encrypt(session_key, toSend));

            out.writeUTF(toSend);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void Receive() {
        try {
            String toPrint = in.readUTF();
            System.out.println(">>> ENC: " + toPrint);
            toPrint = new String(Decrypt(session_key, toPrint), StandardCharsets.UTF_8)
                    .replaceAll(String.valueOf((char) 0), "");

            if (toPrint.equals(exit_word)) {
                System.out.println("SYSTEM: other client has left");
                running = false;
            }
            if (toPrint.equals(send_file_word)) {
                receiveFile();
            }

            System.out.println(">>> " + toPrint);
        } catch (EOFException x) {
            System.out.println("SYSTEM: connection has stopped abruptly, shutting down");
            running = false;
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void send_file() throws IOException {
        System.out.println("SYSTEM: please enter path to a file you want to send: ");
        String filename = brin.readLine();
        Files.readAllBytes(Paths.get(filename));

        // sending file content
        byte[] file_content = Encrypt(session_key, Files.readAllBytes(Paths.get(filename)));
        out.write(file_content);

        // sending checksum
        out.writeUTF(getFileCheckSum(filename));

    }

    private void receiveFile() throws IOException {
        System.out.println("SYSTEM: receiving file ...");
        in.read();
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

