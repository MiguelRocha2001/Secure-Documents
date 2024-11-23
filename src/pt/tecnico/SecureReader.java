package pt.tecnico;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.io.FileReader;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;

import static javax.xml.bind.DatatypeConverter.printHexBinary;

public class SecureReader {

    private static final String MAC_FILENAME = "mac";

    /** Message authentication code algorithm. */
	private static final String MAC_ALGO = "HmacSHA256";

    private static int nounceCounter = 0;
    private static String NOUNCE_FILENAME = "nounce";

    /**
	 * Calculates new digest from text and compare it to the to deciphered digest.
	 */
	private static boolean verifyMAC(byte[] receivedMacBytes, byte[] bytes, SecretKey key) throws Exception {
		Mac mac = Mac.getInstance(MAC_ALGO);
		mac.init(key);
		byte[] recomputedMacBytes = mac.doFinal(bytes);
        System.out.println("Computed cipherDigest:");
        System.out.println(printHexBinary(recomputedMacBytes));

		return Arrays.equals(receivedMacBytes, recomputedMacBytes);
	}

    public static void main(String[] args) throws IOException, Exception {
        // Check arguments
        if (args.length < 1) {
            System.err.println("Argument(s) missing!");
            System.err.printf("Usage: java %s file%n", JsonReader.class.getName());
            return;
        }
        final String filename = args[0];

        // Extract ciphered data
        Path path = Paths.get(filename);
        byte[] encodedCipher = Files.readAllBytes(path);
        byte[] cipherArray = Base64.getDecoder().decode(encodedCipher);

        SecretKey key = Utils.readKey("keys/secret.key");

        // decipher data
        final String CIPHER_ALGO = "AES/ECB/PKCS5Padding";
        System.out.println("Deciphering with " + CIPHER_ALGO + "...");
        Cipher cipher = Cipher.getInstance(CIPHER_ALGO);
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] plainBytes = cipher.doFinal(cipherArray);
        System.out.println("Result: " + plainBytes.length + " bytes");

        System.out.println("Json: " + new String(plainBytes));

        // Extract nounce first
        path = Paths.get(NOUNCE_FILENAME);
        byte[] encodedNounce = Files.readAllBytes(path);
        byte[] nounceArray = Base64.getDecoder().decode(encodedNounce);
        System.out.println(nounceArray.length);
        ByteBuffer nounceBuff = ByteBuffer.wrap(nounceArray); // big-endian by default
        int nounce = nounceBuff.getInt();
        System.out.println("Nounce: " + nounce);
        
        path = Paths.get(MAC_FILENAME);
        byte[] encodedMac = Files.readAllBytes(path);
        byte[] receivedMac = Base64.getDecoder().decode(encodedMac);
        
        System.out.println("Received cipherDigest:");
        System.out.println(printHexBinary(receivedMac));

        byte[] valueToAuthenticate = Utils.concatWithArrayCopy(plainBytes, nounceArray);
        //byte[] valueToAuthenticate = plainBytes;
        
        // verify the MAC
        System.out.println("Verifying...");
        boolean result = verifyMAC(receivedMac, valueToAuthenticate, key);
        System.out.println("MAC is " + (result ? "right" : "wrong"));

        if (nounce == nounceCounter) {
            System.out.println("Nounce is expected.");
            nounceCounter++;
        } else 
            System.out.println("Replay attack detected!");
    }
}
