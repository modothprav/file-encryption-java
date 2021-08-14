import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
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

    private static final String DEFAULT_ALGORITHM = "AES";
    private static final int DEFAULT_KEY_LENGTH = 128;
    private static final String HASH_AlGORITHM = "HmacSHA256";
    private static final String DEFAULT_CIPHER = "AES/CBC/PKCS5PADDING";
    private static final int ITERATION_COUNT = 100000;

    private static String ALGORITHM, CIPHER;
    private static int KEY_LENGTH, BLOCKSIZE;

    // Error Message
    private static final String ERROR_MSG = "\nValid Encryption command: java FileEncryptor enc [Passoword] [inputFile] [outputFile]\n"
    + "\t\t\t  java FileEncryptor enc [Algorithm] [Key length] [Password] [inputFile] [outputFile]\n"
    + "\t\t\t  java FileEncryptor enc [Algorithm] [Password] [inputFile] [outputFile]\n"
    + "\t\t\t  java FileEncryptor enc [Key length] [Password] [inputFile] [outputFile]\n\n"
    + "Valid Decryption command: java FileEncryptor dec [Password] [inputFile] [outputFile]\n\n"
    + "Valid Info command: java FileEncryptor info [filePath]\n\n"
    + "Valid Key lengths: 128, 448, 192, 32 etc\n\n"
    + "NOTE: The only algorithms accepted are AES and Blowfish\n"
    + "NOTE: Must specify a valid Key length (in bits) with respect to the algorithm specified\n"
    + "NOTE: The default Algorithm being used is " + DEFAULT_ALGORITHM + " and the Default Key Length is " + DEFAULT_KEY_LENGTH + " bits\n"
    + "NOTE: If no Algorithm or Key length is specifed the Default values will be used\n";

    public static void main(String[] args) throws Exception {

        if (args.length < 2) { throw new IllegalArgumentException("Not Enough Argunments specified\n" + ERROR_MSG); }

        // Convert String arguments to char arrays
        char[][] charArgs = Util.getCharArguments(args);

        // Clear String argunments
        Arrays.fill(args, null);

        if (Arrays.equals(charArgs[0], "info".toCharArray())) {
            info(new String(charArgs[1]));
            return;
        }

        if (charArgs.length < 4) { throw new IllegalArgumentException("Not Enough Argunments specified\n" + ERROR_MSG); }

        // Options Available
        char[] enc = "enc".toCharArray(), dec = "dec".toCharArray();

        if (!Arrays.equals(charArgs[0], enc) && !Arrays.equals(charArgs[0], dec)) {
            throw new IllegalArgumentException("Neither enc (encrypt), dec (decrypt) or info option specified\n" + ERROR_MSG);
        }

        if (Arrays.equals(charArgs[0], enc)) { // Encrypt

            char[] aes = "AES".toCharArray(), blowfish = "Blowfish".toCharArray();

            int argIndex = 1; // will get incremented everytime a valid argument is encountered
            
            // If incompatiable or no algorithm argument is specified the Default will be applied
            if (Arrays.equals(charArgs[argIndex], aes) || Arrays.equals(charArgs[argIndex], blowfish)) {
                ALGORITHM = new String(charArgs[1]);
                CIPHER = ALGORITHM + "/CBC/PKCS5PADDING";
                argIndex++;
            } else {
                ALGORITHM = DEFAULT_ALGORITHM;
                CIPHER = DEFAULT_CIPHER;
            }

            // Determine blocksize for the IV 
            if (ALGORITHM.equals("AES")) { BLOCKSIZE = 128; }
            if (ALGORITHM.equals("Blowfish")) { BLOCKSIZE = 64; }

            // If no Key length specified then the Default will be applied
            try {
                // Perform Key length checks
                int keyLength = Integer.parseInt(new String(charArgs[argIndex]));
                if (keyLength % 8 != 0) { throw new IllegalArgumentException("Invalid Key Length: not divisible by 8"); }
                
                if (ALGORITHM.equals("AES") && keyLength != 128 && keyLength != 192 && keyLength != 256) {
                    throw new IllegalArgumentException("Invalid Key Length for AES Algorithm, valid key lengths are 128, 192 or 256 bits");
                }

                if (ALGORITHM.equals("Blowfish") && (keyLength < 32 || keyLength > 448)) {
                    throw new IllegalArgumentException("Invalid Key Length for Blowfish Algorithm, valid key lengths are between 32-448 bits");
                }

                KEY_LENGTH = keyLength;
                argIndex++;
            } catch (NumberFormatException e) {
                KEY_LENGTH = DEFAULT_KEY_LENGTH;
            }

            // Check if password and/or file paths have been specified
            if (argIndex + 2 >= charArgs.length) { throw new IllegalArgumentException("Not enough arguments specified" + ERROR_MSG); }
            if (argIndex + 2 <= charArgs.length) { throw new IllegalArgumentException("Invalid arguments please refer to instructions" + ERROR_MSG); }

            encrypt(charArgs[argIndex], new String(charArgs[argIndex + 1]), new String(charArgs[argIndex + 2]));

        } else if (Arrays.equals(charArgs[0], dec)) { // Decrypt
            if (charArgs.length > 4) { throw new IllegalArgumentException("Too many arguments specified for decryption" + ERROR_MSG); }
            decrypt(charArgs[1], new String(charArgs[2]), new String(charArgs[3]));
        }

        // Tear Down, clear arrays
        Arrays.fill(enc, '\0'); Arrays.fill(dec, '\0');

        for (int i = 0; i < charArgs.length; i++) {
            Arrays.fill(charArgs[i], '\0');
        }
        charArgs = null; dec = null; enc = null; 
    }

    /**
     * Encrypts a plain text input file by outputing an encrypted version. It does this 
     * generating a secret key from a passowrd and an initialisation vector which are 
     * used as the specifications during the file encryption process. A message 
     * authentication code is also computed and initialised with the vector and plaintext 
     * values, hence they can be checked for tampering during decryption.
     * 
     * @param password char[] The password specified by the user
     * @param inputPath String specifying the Input path of the plaintext file
     * @param outputPath String specifying the Ouput path of the ciphertext file
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
        final byte[] initVector = new byte[BLOCKSIZE/8], salt = new byte[16], macSalt = new byte[16];

        SecureRandom sr = new SecureRandom();
        sr.nextBytes(initVector); sr.nextBytes(salt); sr.nextBytes(macSalt);

        // Get Keys from password
        final byte[] key = generateKey(password, salt, KEY_LENGTH);
        final byte[] macKey = generateKey(password, macSalt, 256);

        // Password no longer needed
        Arrays.fill(password, '\0'); password = null;

        SecretKeySpec macKeySpec = new SecretKeySpec(macKey, HASH_AlGORITHM);
        Mac hmac = Mac.getInstance(HASH_AlGORITHM);
        hmac.init(macKeySpec);
    
        File outputFile = new File(outputPath);    
        // Create the output file if it doesn't exist
        if (!outputFile.exists()) { outputFile.createNewFile(); }

        final Path plaintextFile = Paths.get(inputPath);
        final Path encryptedFile = Paths.get(outputPath);

        // Convert int to byte array to feed into Hmac
        final byte[] blocksize = ByteBuffer.allocate(8).putInt(BLOCKSIZE).array();
        final byte[] keyLength = ByteBuffer.allocate(8).putInt(KEY_LENGTH/8).array();
        final byte[] algoLength = ByteBuffer.allocate(8).putInt(ALGORITHM.getBytes().length).array();
        
        // Compute Mac for authentication
        final byte[] mac = computeMac(hmac, plaintextFile, blocksize, keyLength, algoLength,
        ALGORITHM.getBytes(), initVector, salt, macSalt);

        // Display the Base64 encoded versions of Key, Vector and computed mac
        displayInformation(getPair("Secret Key", key), getPair("Init Vector", initVector), getPair("Salt", salt), 
        getPair("Mac Key", macKey), getPair("Mac salt", macSalt), getPair("Computed Mac", mac));

        Cipher cipher = createCipher(key, initVector, 1);

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
     * encrypted data, IV, salts and the computed mac is saved as metadata in the encrypted 
     * file with the use of a FileOutputStream. Returns True if the encryption writing 
     * was successfull, False otherwise.
     *  
     * @param inputPath Path The file path of the input file (plaintext)
     * @param outputPath Path The file path of the output file (ciphertext)
     * @param cipher Cipher The cipher instance initialized with the appropriate 
     * specifications in ENCRYPT mode
     * @param salt byte[] The salt used to create key from password
     * @param macSalt byte[] The salt used to create the macKey from password
     * @return boolean True if encryption successful False otherwise
     */
    private static boolean writeEncryptedFile(Path inputPath, Path outputPath, Cipher cipher, byte[] salt, byte[] macSalt, byte[] mac) {
        try (InputStream fin = Files.newInputStream(inputPath);) {
            
            try (FileOutputStream fout = new FileOutputStream(outputPath.toFile());) {
                // Write Metadata
                final byte[] algorithm = ALGORITHM.getBytes();

                fout.write(BLOCKSIZE); fout.write(KEY_LENGTH/8); fout.write(algorithm.length);
                fout.write(algorithm); fout.write(cipher.getIV()); fout.write(salt); 
                fout.write(macSalt); fout.write(mac);

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
     * Decrypts a given cipertext file into its original plaintext form. 
     * A successful decryption occurs when provided with the right password
     * to create the Cipher specifications required for decryption. The 
     * decryption will also fail if any tampering were to be observed. 
     * Will overwrite the resultant output file if it already exists.
     * 
     * @param password char[] The password specified by the user
     * @param inputPath String The input file path (encrypted document)
     * @param outputPath String The file path of the resultant decrypted text
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
     * with the correct key and vector specifications. The IV, salts and mac is read 
     * from the encrypted file as it was saved as metadata during the encryption process. 
     * Decryption will also fail if the computed authentication code doesn't match with 
     * the given authentication code.
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
            BLOCKSIZE = encryptedData.read(); KEY_LENGTH = encryptedData.read() * 8; int algoLength = encryptedData.read();
            ALGORITHM = new String(encryptedData.readNBytes(algoLength)); CIPHER = ALGORITHM + "/CBC/PKCS5PADDING";

            final byte[] initVector = new byte[BLOCKSIZE/8], salt = new byte[16], macSalt = new byte[16], givenMac = new byte[32];
            encryptedData.read(initVector); encryptedData.read(salt); encryptedData.read(macSalt); encryptedData.read(givenMac);

            final byte[] key = generateKey(password, salt, KEY_LENGTH);
            final byte[] macKey = generateKey(password, macSalt, 256);

            // Password no longer needed
            Arrays.fill(password, '\0'); password = null;
            
            // Create key specifications
            SecretKeySpec macKeySpec = new SecretKeySpec(macKey, HASH_AlGORITHM);
            
            // Initialise cipher 
            Cipher cipher = createCipher(key, initVector, 2);

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

            // Convert int to byte array to feed into mac
            final byte[] blocksize = ByteBuffer.allocate(8).putInt(BLOCKSIZE).array();
            final byte[] keyLength = ByteBuffer.allocate(8).putInt(KEY_LENGTH/8).array();
            final byte[] algoLengthArry = ByteBuffer.allocate(8).putInt(ALGORITHM.getBytes().length).array();

            final byte[] computedMac = computeMac(hmac, outputPath, blocksize, keyLength, 
            algoLengthArry, ALGORITHM.getBytes(), initVector, salt, macSalt);
            
            if (!Arrays.equals(givenMac, computedMac)) {
                throw new SecurityException("Authentication failed, file may have been tampered with");
            } 
            
            // Display the Base64 encoded versions of the values used for decryption - for marking and testing
            displayInformation(getPair("Secret Key", key), getPair("Init Vector", initVector), getPair("Salt", salt), 
            getPair("Mac Key", macKey), getPair("Mac salt", macSalt), getPair("Computed Mac", computedMac), 
            getPair("Given Mac", givenMac));
            
            LOG.info("Authentication passed, file integrity maintained");
            
        } catch (IOException ex) {
            Logger.getLogger(FileEncryptor.class.getName()).log(Level.SEVERE, "IOException caught");
            return false;
        } 
        return true;
    }

    /**
     * Allows the user to query metadata for a given file path. The file path 
     * specified must point to an encrypted file with a .enc extension The metadata
     * for the file must also follow a specific format as shown below.
     * Metadata format:
     *  int BLOCKSIZE
     *  int KEY LENGTH (in bytes)
     *  int Algorithm Length 
     *  byte[] Algorithm name
     *  byte[] IV
     *  byte[] Salt
     *  byte[] MacSalt
     *  byte[] Computed Mac
     * 
     * @param String filepath The file being requested to be display the metadata
     */
    private static void info(String filepath) {
        if (!filepath.contains(".enc")) { throw new IllegalArgumentException("Invalid file requested must be an encrypted file e.g. encrypted.enc"); }

        try (InputStream fin = new FileInputStream(new File(filepath))) {
            BLOCKSIZE = fin.read(); KEY_LENGTH = fin.read() * 8; int algoLength = fin.read();
            ALGORITHM = new String(fin.readNBytes(algoLength));

            final byte[] initVector = new byte[BLOCKSIZE/8], salt = new byte[16], macSalt = new byte[16], givenMac = new byte[32];
            fin.read(initVector); fin.read(salt); fin.read(macSalt); fin.read(givenMac);

            System.out.println("\nMetadata for file: " + filepath);

            System.out.print("\n<---------------------------------------->\n");
            System.out.print("Algorithm: " + ALGORITHM + "\nKey length: " + KEY_LENGTH + "\nBlocksize: " + BLOCKSIZE);

            displayInformation(getPair("Init Vector", initVector), getPair("Salt", salt), 
            getPair("Mac salt", macSalt), getPair("Computed Mac", givenMac));

        } catch (IOException e) {
            LOG.warning("Please enter a valid filepath");
        }
    }

    /**
     * Generates a Secret key with a specified password. The password is added with 
     * a salt and iterated multiple times before being hased to increase entropy.
     * The salt and key lenghts need to be specified to then return a secret key 
     * encoded in a byte array. 
     * 
     * @param password char[] The password specified by the user
     * @param salt byte[] A randomly gnerated set of bytes 
     * @param keyLength int The lenght of the final key, in bits e.g. 128, 256 etc.
     * @return byte[] An encoded byte array of the secret key
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    private static byte[] generateKey(char[] password, byte[] salt, int keyLength) throws NoSuchAlgorithmException, 
    InvalidKeySpecException {
        PBEKeySpec passwordKeySpec = new PBEKeySpec(password, salt, ITERATION_COUNT, keyLength);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey secretKey = keyFactory.generateSecret(passwordKeySpec);
        return secretKey.getEncoded();
    }

    /**
     * Creates and initialises a Cipher with the specified key and initialisation vector.
     * The cipher can be initialised in either Encrypt or Decrypt mode. The mode argument
     * specifies which mode to initialise the cipher in. Only two values are accepted by 
     * the 'mode' argunment, 1 for Encryptoin and 2 for Decryption
     * 
     * @param key byte[] The key to be used to generate the cipher
     * @param initVector byte[] The IV to be used to create the cipher
     * @param mode int The mode in which to initialise the cipher, Encrypt = 1; Decrypt = 2
     * @return Cipher The initialised cipher in the specified mode
     * @throws InvalidKeyException
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     */
    private static Cipher createCipher(byte[] key, byte[] initVector, int mode) throws InvalidKeyException, 
    InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException {
        if (mode != 1 && mode != 2) { throw new IllegalArgumentException("Invalid Mode value, Encrypt = 1, Decrypt = 2"); }
        
        // Initialize Parameter specs
        IvParameterSpec iv = new IvParameterSpec(initVector);
        SecretKeySpec skeySpec = new SecretKeySpec(key, ALGORITHM);

        // Initialize cipher 
        Cipher cipher = Cipher.getInstance(CIPHER);
        if (mode == Cipher.ENCRYPT_MODE) { 
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
        } else {
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
        }
        
        return cipher;
    }

    /**
     * Computes a Message authencitaion code for a given inputfile
     * and any metadata that will be added to the file. Takes in an 
     * initialised hmac which gets updated with the file's contents 
     * line by line. Once completed the doFinal method will return a 
     * byte array with the computed Mac.
     * 
     * @param hmac Mac The initialised Mac object
     * @param filePath Path The file path
     * @param metadata byte[] Metadata that will be added to the input file
     * @return byte[] The file's computed Mac
     */
    private static byte[] computeMac(Mac hmac, Path filePath, byte[]... metadata) {
        // feed metadata into mac
        for (byte[] data : metadata) { hmac.update(data); }
        
        // feed input file into mac
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
     * A helper method for displayInformation, creates an Object array which cointans 
     * a name and a value, which can be later used to display it on the console
     * @return Object[] An array consisting of a name and value
     */
    private static Object[] getPair(String name, byte[] value) { return new Object[] {name, value}; }

    /**
     * Allows for the input of any number of object array created by the getPair method.
     * Each object array with it's name and value are printed out in its Base64 encoded 
     * version on the console. Method used for testing and marking purposes.
     * 
     * @param args Object[] Any number of Object arrays consisting of a name and a value
     */
    private static void displayInformation(Object[]... args) {
        System.out.print("\n<---------------------------------------->\n");
        for (Object[] o : args) {
            System.out.println(o[0] + ": " + Base64.getEncoder().encodeToString((byte[]) o[1]));
        }
        System.out.print("<---------------------------------------->\n\n");
    }
}