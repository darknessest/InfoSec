package md5;

public class Test {
    public static void speedTest() {
        String s = "a";
        long endTime, startTime;
        System.out.println("Running different implementations of md5 algorithm for 1*10^6 times");

        startTime = System.nanoTime();
        for (int i = 0; i < 1000000; i++) {
            md5Java.getStringMd5(s);
        }
        endTime = System.nanoTime();
        System.out.println("MD5 with java std libs execution time: " + (endTime - startTime) / 1000000 + "ms");

        startTime = System.nanoTime();
        for (int i = 0; i < 1000000; i++) {
            md5Scratch.toHexString(md5Scratch.computeMD5(s.getBytes()));
        }
        endTime = System.nanoTime();
        System.out.println("MD5 from scratch execution time: " + (endTime - startTime) / 1000000 + "ms");

        startTime = System.nanoTime();
        for (int i = 0; i < 1000000; i++) {
            md5BC.getStringMd5(s);
        }
        endTime = System.nanoTime();
        System.out.println("MD5 with bouncy castle execution time: " + (endTime - startTime) / 1000000 + "ms");
    }

    public static void main(String[] args) {
//        speedTest();

        String filename = "test-1.txt";
        String filename1 = "test-2.txt";
        System.out.println(md5BC.getFileCheckSum(filename));
        System.out.println(md5BC.getFileCheckSum(filename1));
    }
}
