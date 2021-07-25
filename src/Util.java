import java.lang.reflect.Field;
import java.util.Arrays;


/**
 *
 * @author Erik Costlow
 */
public class Util {

    /**
     * Just for nice printing.
     *
     * @param bytes
     * @return A nicely formatted byte string
     */
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString();
    }

    /**
     * Converts an array of Characters into an array of bytes
     * 
     * @param chars An array of characters
     * @return byte[] An array of bytes
     */
    public static byte[] convertCharToByte(char[] chars) {
        byte[] result = new byte[chars.length];
        for (int i = 0; i < chars.length; i++) {
            result[i] = (byte) chars[i];
        }
        return result;
    }

    /**
     * Converts an arry of Strings into a 2-Dimensional array of 
     * characters, each row representing the String as a char array
     * and each column in a row representing the individual char value
     * 
     * @param args String[] An array of strings
     * @return char[][] A 2-Dimensional character array
     */
    public static final char[][] getCharArgunments(String[] args) {
        char[][] charArgs = new char[args.length][];
        for (int i = 0; i < args.length; i++) {
            charArgs[i] = args[i].toCharArray();
        }
        return charArgs;
    }

    /**
     * Replaces the content of internal java.lang.String's char array field 
     * value with symbol \u0000. Obtained from the Blog provided in assignment brief
     * https://konstantinpavlov.net/blog/2015/08/01/secure-java-coding-best-practices/
     * 
     * @param s String The value to be cleared/wiped
     */
    public static void wipeString(String s) {
        try {
            final Field stringValue = String.class.getDeclaredField("value");
            stringValue.setAccessible(true);
            final Object val = stringValue.get(s);
            if (val instanceof byte[]) {
                // in case of compact string in Java 9+
                Arrays.fill((byte[]) val, (byte)0);
            } else {
                Arrays.fill((char[]) val, '\u0000');
            }
            
        } catch (NoSuchFieldException | IllegalAccessException e) {
            throw new Error("Can't wipe string data");
        }
    }
 
}
