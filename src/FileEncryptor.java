import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
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

        if (args.length < 3) { throw new IllegalArgumentException("No Enough Argunments specified\n" + validCmdMsg); }

        if (args[0].equals("enc")) { // Encrypt
            encrypt(args[1], args[2]);
        } else if (args[0].equals("dec")) { // Decrypt

            if (args.length < 5) { throw new IllegalArgumentException("Not Enough Argunments Provided for Decryption\n" + validCmdMsg ); }

            // Decode the Base64 argunments
            byte[] key = Base64.getDecoder().decode(args[1]);
            byte[] initVector = Base64.getDecoder().decode(args[2]);
            
            decrypt(key, initVector, args[3], args[4]);
        } else {
            throw new IllegalArgumentException("Neither enc (encrypt) or dec (decrypt) option specified");
        }  
    }

    public static void encrypt(String inputPath, String outputPath) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException {
        //This snippet is literally copied from SymmetrixExample
        SecureRandom sr = new SecureRandom();
        byte[] key = new byte[16];
        sr.nextBytes(key); // 128 bit key
        byte[] initVector = new byte[16];
        sr.nextBytes(initVector); // 16 bytes IV
        System.out.println("Random key = " + Util.bytesToHex(key));
        System.out.println("initVector = " + Util.bytesToHex(initVector));

        // Display the Base64 encoded versions of Key and Vector
        System.out.print("\n<---------------------------------------->\n");
        System.out.println("Secret Key is: " + Base64.getEncoder().encodeToString(key));
        System.out.println("IV is: " + Base64.getEncoder().encodeToString(initVector));
        System.out.print("<---------------------------------------->\n\n");

        // Initialize Key and Vector Specfications and the Cipher mode
        IvParameterSpec iv = new IvParameterSpec(initVector);
        SecretKeySpec skeySpec = new SecretKeySpec(key, ALGORITHM);
        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

        // Will throw an IOException if input file doens't exist 
        final Path inputFilePath = Paths.get(System.getProperty("user.dir").toString() + inputPath);
    
        File encryptedFile = new File(System.getProperty("user.dir").toString() + outputPath);    
        // Create the output file if it doesn't exist
        if (!encryptedFile.exists()) { encryptedFile.createNewFile(); }
        
        // Perform the encryption and Write out to a CipherOutputStream
        try (InputStream fin = Files.newInputStream(inputFilePath);
                OutputStream fout = new FileOutputStream(encryptedFile);
                CipherOutputStream cipherOut = new CipherOutputStream(fout, cipher) {
        }) {
            final byte[] bytes = new byte[1024];
            for(int length = fin.read(bytes); length != -1; length = fin.read(bytes)){
                cipherOut.write(bytes, 0, length);
            }
        } catch (IOException e) {
            LOG.log(Level.INFO, "Unable to encrypt", e);
        }
        
        LOG.info("Encryption finished, saved at " + encryptedFile);
    }

    public static void decrypt(byte[] key, byte[] initVector, String inputPath, String outputPath) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException {
        // Initialize Key and Vector Specifications and the Cipher Mode
        IvParameterSpec iv = new IvParameterSpec(initVector);
        SecretKeySpec skeySpec = new SecretKeySpec(key, ALGORITHM);
        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

        // Will throw and IOException if the input file doesn't exist
        Path encryptedFile = Paths.get(System.getProperty("user.dir").toString() + inputPath);

        File decryptedFile = new File(System.getProperty("user.dir").toString() + outputPath);
        // Create a new Decrypted file if it doesn't exist
        if (!decryptedFile.exists()) { decryptedFile.createNewFile(); }
        
        // Perform decryption by tyaking in data from a CipherInputStream
        try(InputStream encryptedData = Files.newInputStream(encryptedFile);
            CipherInputStream decryptStream = new CipherInputStream(encryptedData, cipher);
            OutputStream decryptedOut = new FileOutputStream(decryptedFile)) {
            
                final byte[] bytes = new byte[1024];
                for(int length=decryptStream.read(bytes); length!=-1; length = decryptStream.read(bytes)){
                    decryptedOut.write(bytes, 0, length);
                }

        } catch (IOException ex) {
            Logger.getLogger(FileEncryptor.class.getName()).log(Level.SEVERE, "Unable to decrypt", ex);
        }
        
        LOG.info("Decryption complete, open " + decryptedFile);
    }
}