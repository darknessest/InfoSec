package SKD;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;

import static SKD.FileToSend.deserialize;

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
    private static crypto crypto;

    public Chat(boolean isSender) {
        super();
        this.isSender = isSender;
    }

    private static void initServer(int port) {
        try {
            int choice = 0;
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

            byte[] enc_msg = crypto.keyExchange(true, null);
//            System.out.println("SYSTEM: encrypted message: " + org.bouncycastle.util.encoders.Hex.toHexString(enc_msg));

            out.write(enc_msg);

            // only for asymmetric encryption
            byte[] rpk = receiveBytes(2000, false);
            System.out.println("server remote public" + Arrays.toString(rpk));
            crypto.setRemotePublicKey(rpk);

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

            // receiving their key
            byte[] rcvd_msg = receiveBytes(1000, false);
//            System.out.println("client: " + new String(rcvd_msg, StandardCharsets.UTF_8));
            // saving remote public key
            // sending my key (for asymmetric encryption only)
            out.write(crypto.keyExchange(false, rcvd_msg));

//            System.out.println("SYSTEM: encrypted session key: " + rcvd_msg);
//
//            byte[] dec_msg = crypto.DecryptDes(master_key, org.bouncycastle.util.encoders.Hex.decodeStrict(rcvd_msg));
//            String dec_message = new String(dec_msg, StandardCharsets.UTF_8)
//                    .replaceAll(String.valueOf((char) 0), ""); // some trailing NULLS mb present
//
//            session_key = dec_message;
//            System.out.println("SYSTEM: decrypted session key: " + dec_message);

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void Send() {
        try {
            String line = brin.readLine();
            if (line.length() > 0) {
                // Checking for special words
                if (line.equals(exit_word))
                    running = false;
                if (line.equals(send_file_word)) {
                    sendFile();
                    return;
                }

                // Encrypting a message
                byte[] toSend = crypto.Encrypt(line);

                // Sending the message
                out.write(toSend);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void Receive() {
        try {
            byte[] bin_arr = receiveBytes(0, true);
            if (bin_arr.length > 0) {
                System.out.println(">>> ENC: " + org.bouncycastle.util.encoders.Hex.toHexString(bin_arr));

                // Decrypting a message
                String toPrint = new String(crypto.Decrypt(bin_arr), StandardCharsets.UTF_8)
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
            }
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
            // notify about file sending
            out.write(crypto.Encrypt(send_file_word));

            // creating file object
            FileToSend file = new FileToSend(filename, Files.readAllBytes(Paths.get(filename)));

            // waiting for 2 cycles before actually sending
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            // encrypting object and sending
            out.write(crypto.Encrypt(file.serialize()));

            System.out.println("SYSTEM: file was sent");
        } else {
            // if file doesn't exist, stop sending
            System.out.println("SYSTEM: file doesn't exist, aborting ...");

            // TODO: check if useless
            out.write(crypto.Encrypt(send_file_error));
        }
    }

    private void receiveFile() throws IOException {
        System.out.println("SYSTEM: receiving file ...");


        byte[] file_bin = receiveBytes(1000, false);

        // decrypting file
        FileToSend file = deserialize(crypto.Decrypt(file_bin));

        // saving file
        assert file != null;
        file.setName("_".concat(file.getName()));
        if (file.saveFile() == 0)
            System.out.println("SYSTEM: file received, and saved: " + file.getName());
        else
            System.out.println("SYSTEM: file wasn't saved");

        // comparing checksum
        String recalc_checksum = crypto.getFileMd5(file.getName());
        System.out.println("SYSTEM: sent file checksum:\t" + file.getChecksum());
        System.out.println("SYSTEM: received file checksum:\t" + recalc_checksum);

        assert recalc_checksum != null;
        if (recalc_checksum.equals(file.getChecksum()))
            System.out.println("SYSTEM: checksums are identical");
        else
            System.out.println("SYSTEM: checksums are different");
    }

    private static byte[] receiveBytes(int sleep, boolean ignore) {
        if (sleep > 0)
            try {
                Thread.sleep(sleep);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }

        // receiving file
        int count = 0;
        byte[] bin_arr = null;
        try {
            count = in.available();

            bin_arr = new byte[count];

            if (in.read(bin_arr) == 0 && !ignore) {
                System.out.println("SYSTEM: data wasn't received. aborting ...");
//                return null;
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return bin_arr;
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
        brin = new BufferedReader(new InputStreamReader(System.in));
        int choice = 0;
        String type = "";

        // TODO: add while until correct choices are made
        System.out.println("Enter encryption method: (RSA or DES)");

        try {
            type = brin.readLine();
        } catch (IOException e) {
            e.printStackTrace();
        }
        crypto = new crypto(type);


        System.out.println("1) To start a server");
        System.out.println("2) To start a client");

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
