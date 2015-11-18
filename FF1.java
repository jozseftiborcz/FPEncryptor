import java.nio.file.Files;
import java.nio.file.Paths;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

public class FF1 {

    final public static boolean debug = false;
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

    /**
     * It converts a byte seq to radix based bit string. The maximum possible value should be less then 64 bit.
     */
    public static long intStr2Num(String input) {
        return Long.parseLong(input, 10);
    }

    public static String num2IntStr(long num, int length) {
        String s = Long.toString(num, 10);
        while (s.length() < length) s = "0"+s;
        return s;
    }

    // based on NIST SP800 38g, FF2
    public static String encryptCCN(SecretKey key, String tweak, String input) throws Exception {
        long ccn = intStr2Num(input);
        int A = (int) ccn>>10;
        int B = (int) ccn&0x3ff;
        byte radix = 0x0a;
        Cipher aes = Cipher.getInstance("AES/ECB/NoPadding");
        aes.init(Cipher.ENCRYPT_MODE, key); //, iv);
        byte[] P = new byte[16];
        if (tweak.length()>0) {
            P[0] = radix;
            P[1] = (byte) (tweak.length() & 0xff);
            P[2] = 0x06; // length of CCN middle part to encrypt
            for(int i=3;i<11;i++) P[i] = 0;
            long twn = Long.parseLong(tweak, 10); // should fit within 5 bytes
            P[11] = (byte) (twn >> 32 & 0xff);
            P[12] = (byte) (twn >> 24 & 0xff);
            P[13] = (byte) (twn >> 16 & 0xff);
            P[14] = (byte) (twn >> 8 & 0xff);
            P[15] = (byte) (twn & 0xff);
        }
        byte[] encryptionKey = aes.doFinal(P);
        aes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(encryptionKey, "AES")); //, iv);
        for (int i=0; i<10; i++) {
            int a = A;
            int b = B;
            byte[] Q = new byte[16];
            Q[0] = (byte) i;
            Q[14] = (byte) ((B >> 8) & 0xff); // two bytes are enough
            Q[15] = (byte) (B & 0xff);
            byte[] Y = aes.doFinal(Q);
            int y = (((int)Y[14]&0x03)<<8)+((int)Y[15]&0xff);
            if (debug) System.out.println(bytesToHex(Q) + " -> y" + y);
            int C = A^y;
            A = B;
            B = C;
            if (debug) System.out.println("encr: A " +a+ " B " + b + " -> " + "A " +A+ " B " + B);
        }
        String eccn = num2IntStr((A<<10)+B,6);
        if (eccn.length()>6) return encryptCCN(key, tweak, eccn); else return eccn;
    }

    public static String decryptCCN(SecretKey key, String tweak, String input) throws Exception {
        long ccn = intStr2Num(input);
        int A = (int) ccn>>10;
        int B = (int) ccn&0x3ff;
        byte radix = 0x0a;
        Cipher aes = Cipher.getInstance("AES/ECB/NoPadding");
        aes.init(Cipher.ENCRYPT_MODE, key); //, iv);
        byte[] P = new byte[16];
        if (tweak.length()>0) {
            P[0] = radix;
            P[1] = (byte) (tweak.length() & 0xff);
            P[2] = 0x06; // length of CCN middle part to encrypt
            for(int i=3;i<11;i++) P[i] = 0;
            long twn = Long.parseLong(tweak, 10); // should fit within 5 bytes
            P[11] = (byte) (twn >> 32 & 0xff);
            P[12] = (byte) (twn >> 24 & 0xff);
            P[13] = (byte) (twn >> 16 & 0xff);
            P[14] = (byte) (twn >> 8 & 0xff);
            P[15] = (byte) (twn & 0xff);
        }
        byte[] encryptionKey = aes.doFinal(P);
        aes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(encryptionKey, "AES")); //, iv);
        for (int i=9; i>=0; i--) {
            int a = A;
            int b = B;
            byte[] Q = new byte[16];
            Q[0] = (byte) i;
            Q[14] = (byte) ((A >> 8) & 0xff); // two bytes are enough
            Q[15] = (byte) (A & 0xff);
            byte[] Y = aes.doFinal(Q);
            int y = (((int)Y[14]&0x03)<<8)+((int)Y[15]&0xff);
            if (debug) System.out.println(bytesToHex(Q) + " -> y" + y);
            int C = B^y;
            B = A;
            A = C;
            if (debug) System.out.println("decr: A " +a+ " B " + b + " -> " + "A " +A+ " B " + B);
        }
        String eccn = num2IntStr((A<<10)+B,6);
        if (eccn.length()>6) return decryptCCN(key, tweak, eccn); else return eccn;
    }

    public static void main(String[] args) throws Exception {
        KeyGenerator KeyGen = KeyGenerator.getInstance("AES");
        KeyGen.init(128);

        SecretKey key = KeyGen.generateKey();
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");

        byte iv[] = new byte[16];
        sr.nextBytes(iv);
        IvParameterSpec ivs = new IvParameterSpec(iv);
//        System.out.println(encryptCCN(key, ivs, "1234561234", "123456"));
        for (String ccn : new String[]{"1234561234561234", "1234562345611234", "2234561234561234", "6543211234564321", "4321654321654321"}) {
            String tweak = ccn.substring(0,6)+ccn.substring(12);
            String pan = ccn.substring(6,12); 
            String epan = encryptCCN(key, tweak, pan);
            System.out.println(pan + "->" + epan + "("+tweak+")->" + decryptCCN(key, tweak, epan));
        }
        /*
        System.out.println(encryptCCN(key, ivs, "2234561234", "123456"));
        System.out.println(decryptCCN(key, ivs, "2234561234", encryptCCN(key, ivs, "2234561234", "123456")));
        System.out.println(encryptCCN(key, ivs, "1234561234", "223456"));
        System.out.println(decryptCCN(key, ivs, "1234561234", encryptCCN(key, ivs, "1234561234", "223456")));
        System.out.println(encryptCCN(key, ivs, "1234561234", "323456"));
        System.out.println(decryptCCN(key, ivs, "1234561234", encryptCCN(key, ivs, "1234561234", "323456")));
        System.out.println(encryptCCN(key, ivs, "1234561234", "523456"));
        System.out.println(decryptCCN(key, ivs, "1234561234", encryptCCN(key, ivs, "1234561234", "523456")));
        */
    }
}
