package pt.tecnico;

import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import static javax.xml.bind.DatatypeConverter.printHexBinary;

import com.google.gson.*;

import java.security.SecureRandom;

/**
 * Example of JSON writer.
 */
public class SecureWriter {

    private static final String MAC_FILENAME = "mac";

    /** Message authentication code algorithm. */
    private static final String MAC_ALGO = "HmacSHA256";

    private static int nounceCounter = 0;
    private static String NOUNCE_FILENAME = "nounce";

    /*
    private static final long FRESH_TOKEN_SEED = generateSecureSeed();

    private static long generateSecureSeed() throws NoSuchAlgorithmException {
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");

		System.out.println("Generating random byte array ...");

		final byte array[] = new byte[8];
		random.nextBytes(array);

        long seed = new BigInteger(array).longValue();

		//System.out.print("Results: ");
		//System.out.println(printHexBinary(array));

        return seed;
    }
    */

    /** Makes a message authentication code. */
	private static byte[] makeMAC(byte[] bytes, SecretKey key) throws Exception {
		Mac mac = Mac.getInstance(MAC_ALGO);
		mac.init(key);
		byte[] macBytes = mac.doFinal(bytes);

		return macBytes;
	}

    public static void main(String[] args) throws IOException, Exception {
        // Check arguments
        if (args.length < 1) {
            System.err.println("Argument(s) missing!");
            System.err.printf("Usage: java %s file%n", JsonWriter.class.getName());
            return;
        }
        final String filename = args[0];

        // Create bank statement JSON object
        JsonObject jsonObject = new JsonObject();

        JsonObject headerObject = new JsonObject();
        headerObject.addProperty("author", "Ultron");
        headerObject.addProperty("version", 2);
        headerObject.addProperty("title", "Some Title");
        JsonArray tagsArray = new JsonArray();
        tagsArray.add("robot");
        tagsArray.add("autonomy");
        headerObject.add("tags", tagsArray);
        jsonObject.add("header", headerObject);

        jsonObject.addProperty("body", "I had strings but now I'm free");

        jsonObject.addProperty("status", "draft");

        SecretKey key = Utils.readKey("keys/secret.key");

        byte[] plainBytes = jsonObject.toString().getBytes();

        // cipher data
        final String CIPHER_ALGO = "AES/ECB/PKCS5Padding";
        System.out.println("Ciphering with " + CIPHER_ALGO + "...");
        Cipher cipher = Cipher.getInstance(CIPHER_ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] cipherBytes = cipher.doFinal(plainBytes);
        System.out.println("Result: " + cipherBytes.length + " bytes");

        String cipherB64dString = Base64.getEncoder().encodeToString(cipherBytes);
        System.out.println("Cipher result, encoded as base 64 string: " + cipherB64dString);

        // Write ciphered JSON to file
        try (FileWriter fileWriter = new FileWriter(filename)) {
            fileWriter.write(cipherB64dString);
        }
        
        byte[] nounceByteArray = ByteBuffer.allocate(4).putInt(nounceCounter).array();

        // For freshness, use a counter
        // Write JSON object to file
        try (FileWriter fileWriter = new FileWriter(NOUNCE_FILENAME)) {
            String encodedNounce = Base64.getEncoder().encodeToString(nounceByteArray);
            fileWriter.write(encodedNounce);
            nounceCounter++; // Advance counter
        }

        
        // Add integrity protection
        // For now, use symetric criptography
        
        System.out.println(jsonObject.toString());

        byte[] dataToAuthenticate = Utils.concatWithArrayCopy(plainBytes, nounceByteArray);
        //byte[] dataToAuthenticate = plainBytes;
        
        // make MAC
		System.out.println("Signing...");
		byte[] cipherDigest = makeMAC(dataToAuthenticate, key);
		System.out.println("CipherDigest:");
		System.out.println(printHexBinary(cipherDigest));
            
        // Append MAC to message
        try (FileWriter fileWriter = new FileWriter(MAC_FILENAME)) {
            String encodedString = Base64.getEncoder().encodeToString(cipherDigest);
            fileWriter.write(encodedString);
        }

    }
}
