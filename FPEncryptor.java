import java.nio.file.Files;
import java.nio.file.Paths;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;

public class FPEncryptor {

    final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();

    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 4];

        java.util.Arrays.fill(hexChars, ' ');
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 3] = hexArray[v >>> 4];
            hexChars[j * 3 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    public static void main(String[] args) throws Exception {
//        String inputText = args[0];

        KeyGenerator KeyGen = KeyGenerator.getInstance("AES");
        KeyGen.init(128);

        SecretKey SecKey = KeyGen.generateKey();

        Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");



//        System.out.println(byteText.length);
        byte[] byteText = ("Your Plain Text Here").getBytes();
        aes.init(Cipher.ENCRYPT_MODE, SecKey);
        byte[] byteCipherText = aes.doFinal(byteText);
        long start = System.nanoTime();
        System.out.println(start);
        for (int i=0; i<10000; ++i) {
            //System.out.println(bytesToHex(byteCipherText));
            //System.out.println(byteCipherText.length);
            aes.init(Cipher.DECRYPT_MODE, SecKey, new IvParameterSpec(aes.getIV()));
            byte[] bytePlainText = aes.doFinal(byteCipherText);
            //System.out.println(bytePlainText.length);
            //System.out.println(new String(bytePlainText));
        }
        long end = System.nanoTime()-start;
        System.out.println(end);
        System.out.println(end/1000000000L);
            /*
        byte[] cipherText = Files.readAllBytes(Paths.get(FileName));

        aes.init(Cipher.DECRYPT_MODE, SecKey);
        byte[] bytePlainText = aes.doFinal(cipherText);
        Files.write(Paths.get(FileName2), bytePlainText);
        */
    }
}
