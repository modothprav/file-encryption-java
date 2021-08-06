import java.io.File;
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
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;


/**
 *
 * @author Erik Costlow
 * @author Pravin Modotholi
 */
public class FileEncryptor {
    private static final Logger LOG = Logger.getLogger(FileEncryptor.class.getSimpleName());

    private static final String ALGORITHM = "AES";
    private static final String HASH_AlGORITHM = "HmacSHA256";
    private static final String CIPHER = "AES/CBC/PKCS5PADDING";
    private static final int ITERATION_COUNT = 1000 * 128;

    public static void main(String[] args) throws Exception {
        // Error Message
        final String validCmdMsg = "Valid Encryption command: java FileEncryptor enc [Password] [inputFile] [outputFile]\n"
        + "Valid Decryption command: java FileEncryptor dec [Password] [inputFile] [outputFile]\n";

        if (args.length < 4) { throw new IllegalArgumentException("Not Enough Argunments specified\n" + validCmdMsg); }

        // Convert String arguments to char arrays
        char[][] charArgs = Util.getCharArguments(args);

        // Clear String argunments
        Arrays.fill(args, null);

        // Options Available
        char[] enc = "enc".toCharArray();
        char[] dec = "dec".toCharArray();

        if (!Arrays.equals(charArgs[0], enc) && !Arrays.equals(charArgs[0], dec)) {
            throw new IllegalArgumentException("Neither enc (encrypt) or dec (decrypt) option specified\n" + validCmdMsg);
        }

        if (Arrays.equals(charArgs[0], enc)) { // Encrypt
            encrypt(charArgs[1], new String(charArgs[2]), new String(charArgs[3]));

        } else if (Arrays.equals(charArgs[0], dec)) { // Decrypt
            decrypt(charArgs[1], new String(charArgs[2]), new String(charArgs[3]));
        
        }

        // Tear Down, clear arrays
        Arrays.fill(enc, '\0'); Arrays.fill(dec, '\0');

        for (int i = 0; i < charArgs.length; i++) {
            Arrays.fill(charArgs[i], '\0');
        }
        charArgs = null; dec = null; enc = null; 
    }

    private static byte[] generateKey(char[] password, byte[] salt, int keyLength) throws NoSuchAlgorithmException, 
    InvalidKeySpecException {
        PBEKeySpec passwordKeySpec = new PBEKeySpec(password, salt, ITERATION_COUNT, keyLength);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey secretKey = keyFactory.generateSecret(passwordKeySpec);
        return secretKey.getEncoded();
    }

    /**
     * Encrypts a plain text input file by outputing an encrypted version. It does this 
     * generating a 128 bit secret key and initialisation vector which are used as the 
     * specifications during the file encryption process. A message aithentication code 
     * is also computed with the intialisaton vector and plaintext values, hence these 
     * values can be checked for tampering during decryption.
     * 
     * @param key byte[] The secrect key which will be used to encrypt the file
     * @param inputPath - A String specifying the Input path of the plaintext file
     * @param outputPath - A String specifying the Ouput path of the ciphertext file
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws InvalidAlgorithmParameterException
     * @throws IOException
     * @throws InvalidKeySpecException
     */
    public static void encrypt(char[] password, String inputPath, String outputPath) throws NoSuchAlgorithmException, 
    NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException, InvalidKeySpecException {
        //Generate vector and salts
        final byte[] initVector = new byte[16];
        final byte[] salt = new byte[16];
        final byte[] macSalt = new byte[16];

        SecureRandom sr = new SecureRandom();
        sr.nextBytes(initVector); 
        sr.nextBytes(salt);
        sr.nextBytes(macSalt);

        // Get Keys from password
        final byte[] key = generateKey(password, salt, 128);
        final byte[] macKey = generateKey(password, macSalt, 256);

        // Initialize Vector and Keys
        IvParameterSpec iv = new IvParameterSpec(initVector);
        SecretKeySpec skeySpec = new SecretKeySpec(key, ALGORITHM);
        SecretKeySpec macKeySpec = new SecretKeySpec(macKey, HASH_AlGORITHM);

        // Initialize cipher and Mac
        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
        
        Mac hmac = Mac.getInstance(HASH_AlGORITHM);
        hmac.init(macKeySpec);
    
        File outputFile = new File(outputPath);    
        // Create the output file if it doesn't exist
        if (!outputFile.exists()) { outputFile.createNewFile(); }

        final Path plaintextFile = Paths.get(inputPath);
        final Path encryptedFile = Paths.get(outputPath);

        // Compute Mac for authentication
        hmac.update(initVector);
        hmac.update(salt);
        hmac.update(macSalt);
        final byte[] mac = computeMac(hmac, plaintextFile);

        // Display the Base64 encoded versions of Key, Vector and computed mac
        System.out.print("\n<---------------------------------------->\n");
        System.out.println("Secret Key is: " + Base64.getEncoder().encodeToString(key));
        System.out.println("IV is: " + Base64.getEncoder().encodeToString(initVector));
        System.out.println("Computed Mac: " + Base64.getEncoder().encodeToString(mac));
        System.out.print("<---------------------------------------->\n\n");

        // Write plaintext into ciphertext
        if (writeEncryptedFile(plaintextFile, encryptedFile, cipher, salt, macSalt, mac)) {
            LOG.info("Encryption finished, saved at " + encryptedFile);
        } else {
            LOG.log(Level.WARNING, "Encryption Failed");
        }
    }

    /**
     * Writes an encrypted version of the input file, into a new output file.
     * Uses a FileInputStream to read the plaintext file and wraps the OutputStream
     * with a CipherOutStream to write an encrypted version. Prior to writing the 
     * encrypted data, IV and the computed mac is saved as metadata in the encrypted 
     * file with the use of a FileOutputStream. Returns True if the encryption writing 
     * was successfull, False otherwise.
     *  
     * @param inputPath Path The file path of the input file (plaintext)
     * @param outputPath Path The file path of the output file (ciphertext)
     * @param cipher Cipher The cipher instance initialized with the appropriate 
     * specifications in ENCRYPT mode
     * @return boolean True if encryption successful False otherwise
     */
    private static boolean writeEncryptedFile(Path inputPath, Path outputPath, Cipher cipher, byte[] salt, byte[] macSalt, byte[] mac) {
        try (InputStream fin = Files.newInputStream(inputPath);) {
            
            try (FileOutputStream fout = new FileOutputStream(outputPath.toFile());) {
                // Write Metadata
                fout.write(cipher.getIV());
                fout.write(salt);
                fout.write(macSalt);
                fout.write(mac);

                try (CipherOutputStream cipherOut = new CipherOutputStream(fout, cipher);) {
                    final byte[] bytes = new byte[1024];
                    for(int length = fin.read(bytes); length != -1; length = fin.read(bytes)){
                        cipherOut.write(bytes, 0, length);
                    }
                }
            }
        } catch (IOException e) {
            LOG.log(Level.WARNING, "Ensure Valid File paths are specified.");
            return false;
        }

        return true;
    }

    /**
     * Computes a Message authencitaion code for a given inputfile
     * Takes in an initialised hmac which gets updated with the file's
     * contents line by line. Once completed the doFinal method will 
     * return a byte array with the computed Mac.
     * 
     * @param hmac Mac The initialised Mac object
     * @param filePath Path The file path
     * @return byte[] The file's computed Mac
     */
    private static byte[] computeMac(Mac hmac, Path filePath) {
        try (InputStream fin = Files.newInputStream(filePath);) {
            final byte[] bytes = new byte[1024];
            for(int length = fin.read(bytes); length != -1; length = fin.read(bytes)){
                hmac.update(bytes, 0, length);
            }
        } catch (IOException e) {
            LOG.log(Level.SEVERE, "IOException caught - Please check filepath specified");
            System.exit(0);
        }

        return hmac.doFinal();
    }

    /**
     * Decrypts a given cipertext file into its original plaintext form. 
     * A successful decryption occurs when provided with the right key
     * to create the Cipher specifications required for decryption. 
     * Will overwrite the resultant output file if it already exists.
     * 
     * @param key byte[] - The Key used to originally encrypt the input file 
     * @param inputPath String - The input file path (encrypted document)
     * @param outputPath String - The file path of the resultant decrypted text
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws InvalidAlgorithmParameterException
     * @throws IOException
     * @throws InvalidKeySpecException
     */
    public static void decrypt(char[] password, String inputPath, String outputPath) throws IOException, 
    NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, 
    InvalidKeySpecException{
        
        File outputFile = new File(outputPath);
        // Create a new Output file if it doesn't exist
        if (!outputFile.exists()) { outputFile.createNewFile(); }

        final Path encryptedFile = Paths.get(inputPath);
        final Path decryptedFile = Paths.get(outputPath);
        
        if (writeDecryptedFile(encryptedFile, decryptedFile, password)) {
            LOG.info("Decryption complete, open " + decryptedFile);
        } else {
            LOG.log(Level.SEVERE, "Decryption failed: Ensure the correct Key and Files paths are specified");
        }
    }

    /**
     * Reads an encrypted file by wrapping an InputStream with a CipherInputStream
     * The encrypted files gets decrypted and written out to the output file. 
     * For a successful decryption the Cipher needs to be initialized in DECRYPT mode
     * with the correct key and vector specifications. The IV is read from the encrypted
     * file as it was saved unencrypted during the encryption process. Decryption will 
     * also fail if the computed authentication code doesn't match with the given 
     * authentication code, which it also reads from the encrpted file.
     * 
     * @param inputPath Path The input file path (encrypted file)
     * @param outputPath Path The output file path (decrypted file)
     * @param password char[] The password entered by the user 
     * @return boolean True if Decryption is successful False otherwise
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeySpecException
     */
    private static boolean writeDecryptedFile(Path inputPath, Path outputPath, char[] password) throws NoSuchAlgorithmException, 
    NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, InvalidKeySpecException {
        try (InputStream encryptedData = Files.newInputStream(inputPath);){
        
            // Read metadata from the input file
            final byte[] initVector = new byte[16];
            final byte[] salt = new byte[16];
            final byte[] macSalt = new byte[16];
            final byte[] givenMac = new byte[32];
            
            encryptedData.read(initVector);
            encryptedData.read(salt);
            encryptedData.read(macSalt);
            encryptedData.read(givenMac);

            final byte[] key = generateKey(password, salt, 128);
            final byte[] macKey = generateKey(password, macSalt, 256);
            
            // Create key specifications
            IvParameterSpec iv = new IvParameterSpec(initVector);
            SecretKeySpec skeySpec = new SecretKeySpec(key, ALGORITHM);
            SecretKeySpec macKeySpec = new SecretKeySpec(macKey, HASH_AlGORITHM);
            
            // Initialise cipher 
            Cipher cipher = Cipher.getInstance(CIPHER);
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

            // Read cipertext data and write plaintext data
            try (CipherInputStream decryptStream = new CipherInputStream(encryptedData, cipher);) {
                try (OutputStream decryptedOut = Files.newOutputStream(outputPath);) {
                    final byte[] bytes = new byte[1024];
                    for(int length=decryptStream.read(bytes); length!=-1; length = decryptStream.read(bytes)){
                        decryptedOut.write(bytes, 0, length);
                    }
                }
            } 
            
            // Check authentication and file integerity
            Mac hmac = Mac.getInstance(HASH_AlGORITHM);
            hmac.init(macKeySpec);

            hmac.update(initVector);
            hmac.update(salt);
            hmac.update(macSalt);
            final byte[] computedMac = computeMac(hmac, outputPath);
            if (!Arrays.equals(givenMac, computedMac)) {
                throw new SecurityException("Authentication failed, file may have been tampered with");
            } 
                
            LOG.info("Authentication passed, file integrity maintained");
            
        } catch (IOException ex) {
            Logger.getLogger(FileEncryptor.class.getName()).log(Level.SEVERE, "IOException caught");
            return false;
        } 
        return true;
    }
}