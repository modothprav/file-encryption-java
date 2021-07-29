import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


/**
 *
 * @author Erik Costlow
 * @author Pravin Modotholi
 */
public class FileEncryptor {
    private static final Logger LOG = Logger.getLogger(FileEncryptor.class.getSimpleName());

    private static final String ALGORITHM = "AES";
    private static final String CIPHER = "AES/CBC/PKCS5PADDING";

    public static void main(String[] args) throws Exception {
        // Error Message
        final String validCmdMsg = "Valid Encryption command: java FileEncryptor enc [inputFile] [outputFile]\n"
        + "Valid Decryption command: java FileEncryptor dec [Key] [Vector] [inputFile] [outputFile]";

        if (args.length < 3) { throw new IllegalArgumentException("Not Enough Argunments specified\n" + validCmdMsg); }

        // Convert String arguments to char arrays
        char[][] charArgs = Util.getCharArgunments(args);

        // Clear String argunments
        Arrays.fill(args, null);

        if (Arrays.equals(charArgs[0], "enc".toCharArray())) { // Encrypt
            encrypt(new String(charArgs[1]), new String(charArgs[2]));
        
        } else if (Arrays.equals(charArgs[0], "dec".toCharArray())) { // Decrypt

            if (charArgs.length < 5) { throw new IllegalArgumentException("Not Enough Argunments Provided for Decryption\n" + validCmdMsg ); }

            // Decode the Base64 argunments
            byte[] key = Base64.getDecoder().decode(Util.convertCharToByte(charArgs[1]));
            byte[] initVector = Base64.getDecoder().decode(Util.convertCharToByte(charArgs[2]));
            
            decrypt(key, initVector, new String(charArgs[3]), new String(charArgs[4]));

            // Tear Down, clear arrays
            Arrays.fill(key, (byte) 0);
            Arrays.fill(initVector, (byte) 0);
            key = null; initVector = null;

            for (int i = 0; i < charArgs.length; i++) {
                Arrays.fill(charArgs[i], '\0');
            }
            charArgs = null;

        } else {
            throw new IllegalArgumentException("Neither enc (encrypt) or dec (decrypt) option specified\n" + validCmdMsg);
        }  
    }

    /**
     * Encrypts a plain text input file by outputing an encrypted version. It does this 
     * generating a 128 bit secret key and initialisation vector which are used as the 
     * specifications during the file encryption process.
     * 
     * @param inputPath - A String specifying the Input path of the plaintext file
     * @param outputPath - A String specifying the Ouput path of the ciphertext file
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws InvalidAlgorithmParameterException
     * @throws IOException
     */
    public static void encrypt(String inputPath, String outputPath) throws NoSuchAlgorithmException, 
    NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException {
        //This snippet is literally copied from SymmetrixExample
        SecureRandom sr = new SecureRandom();
        byte[] key = new byte[16];
        sr.nextBytes(key); // 128 bit key
        byte[] initVector = new byte[16];
        sr.nextBytes(initVector); // 16 bytes IV

        // Display the Base64 encoded versions of Key and Vector
        System.out.print("\n<---------------------------------------->\n");
        System.out.println("Secret Key is: " + Base64.getEncoder().encodeToString(key));
        System.out.println("IV is: " + Base64.getEncoder().encodeToString(initVector));
        System.out.print("<---------------------------------------->\n\n");

        // Initialize Key, Vector Specfications and the Cipher mode
        IvParameterSpec iv = new IvParameterSpec(initVector);
        SecretKeySpec skeySpec = new SecretKeySpec(key, ALGORITHM);
        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
    
        File outputFile = new File(outputPath);    
        // Create the output file if it doesn't exist
        if (!outputFile.exists()) { outputFile.createNewFile(); }

        final Path plaintextFile = Paths.get(inputPath);
        final Path encryptedFile = Paths.get(outputPath);

        // Write plaintext into ciphertext
        if (writeEncryptedFile(plaintextFile, encryptedFile, cipher)) {
            LOG.info("Encryption finished, saved at " + encryptedFile);
        } else {
            LOG.log(Level.WARNING, "Encryption Failed, Ensure Valid File Paths are specified");
        }
    }

    /**
     * Writes an encrypted version of the input file, into the output file.
     * Uses a FileInputStream to read the plaintext file and wraps the OutputStream
     * with a CipherOutStream to write an encrypted version of the plaintext file.
     * Returns True if the encryption writing was successfull, False otherwise.
     *  
     * @param inputPath Path The file path of the input file (plaintext)
     * @param outputPath Path The file path of the output file (ciphertext)
     * @param cipher Cipher The cipher instance initialized with the appropriate 
     * specifications in ENCRYPT mode
     * @return boolean True if encryption successful False otherwise
     */
    private static boolean writeEncryptedFile(Path inputPath, Path outputPath, Cipher cipher) {
        try (InputStream fin = Files.newInputStream(inputPath);
            OutputStream fout = Files.newOutputStream(outputPath);
            CipherOutputStream cipherOut = new CipherOutputStream(fout, cipher) {
        }) {
            final byte[] bytes = new byte[1024];
            for(int length = fin.read(bytes); length != -1; length = fin.read(bytes)){
                cipherOut.write(bytes, 0, length);
            }
        } catch (IOException e) {
            LOG.log(Level.INFO, "Unable to encrypt");
            return false;
        }

        return true;
    }

    /**
     * Decrypts a given cipertext file into its original plaintext form. 
     * A successful decryption occurs when provided with the right key and 
     * initialisation vector to create the Cipher specifications required 
     * for decryption. Will overwrite the resultant output file if it 
     * already exists.
     * 
     * @param key byte[] - The Key used to originally encrypt the input file 
     * @param initVector byte[] - The initialisation vector originally used for encryption
     * @param inputPath String - The input file path (encrypted document)
     * @param outputPath String - The file path of the resultant decrypted text
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws InvalidAlgorithmParameterException
     * @throws IOException
     */
    public static void decrypt(byte[] key, byte[] initVector, String inputPath, String outputPath) throws NoSuchAlgorithmException, 
    NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException {
        // Initialize Key and Vector Specifications and the Cipher Mode
        IvParameterSpec iv = new IvParameterSpec(initVector);
        SecretKeySpec skeySpec = new SecretKeySpec(key, ALGORITHM);
        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

        File outputFile = new File(outputPath);
        // Create a new Output file if it doesn't exist
        if (!outputFile.exists()) { outputFile.createNewFile(); }

        final Path encryptedFile = Paths.get(inputPath);
        final Path decryptedFile = Paths.get(outputPath);
        
        if (writeDecryptedFile(encryptedFile, decryptedFile, cipher)) {
            LOG.info("Decryption complete, open " + decryptedFile);
        } else {
            LOG.log(Level.SEVERE, "Ensure the correct Key, Vector, and Files paths are specified");
        }
    }

    /**
     * Reads an encrypted file by wrapping an InputStream with a CipherInputStream
     * The encrypted files gets decrypted and written out to the output file. 
     * For a successful decryption the Cipher new to be initialized in DECRYPT mode
     * with the correct key and vector specifications. 
     * 
     * @param inputPath Path The input file path (encrypted file)
     * @param outputPath Path The output file path (decrypted file)
     * @param cipher Cipher The cipher instance initialized with the appropriate 
     * specifications in DECRYPT mode
     * @return boolean True if Decryption is successful False otherwise
     */
    private static boolean writeDecryptedFile(Path inputPath, Path outputPath, Cipher cipher) {
        try(InputStream encryptedData = Files.newInputStream(inputPath);
            CipherInputStream decryptStream = new CipherInputStream(encryptedData, cipher);
            OutputStream decryptedOut = Files.newOutputStream(outputPath)) {
            
                final byte[] bytes = new byte[1024];
                for(int length=decryptStream.read(bytes); length!=-1; length = decryptStream.read(bytes)){
                    decryptedOut.write(bytes, 0, length);
                }

        } catch (IOException ex) {
            Logger.getLogger(FileEncryptor.class.getName()).log(Level.SEVERE, "Unable to decrypt");
            return false;
        }
        return true;
    }
}