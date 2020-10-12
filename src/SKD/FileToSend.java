package SKD;

import java.io.*;


public class FileToSend implements Serializable {
    private String name;
    private final byte[] payload;
    private final String checksum;

    public FileToSend(String name, byte[] payload) {
        this.name = name;
        this.payload = payload;
        this.checksum = crypto.getBytesMd5(payload);
    }

    public String getName() {
        return name;
    }

    public byte[] getPayload() {
        return payload;
    }

    public String getChecksum() {
        return checksum;
    }

    public void setName(String name) {
        this.name = name;
    }

    public int saveFile() {
        OutputStream os;
        try {
            os = new FileOutputStream(this.name);
            os.write(payload);

            os.close();
            return 0;
        } catch (IOException e) {
            e.printStackTrace();
            return -1;
        }
    }

    public byte[] serialize() throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ObjectOutputStream os = new ObjectOutputStream(out);
        os.writeObject(this);
        return out.toByteArray();
    }

    public static FileToSend deserialize(byte[] data) throws IOException {
        ByteArrayInputStream in = new ByteArrayInputStream(data);
        ObjectInputStream is = new ObjectInputStream(in);
        try {
            return (FileToSend) is.readObject();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
            return null;
        }
    }
}
