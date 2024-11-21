package pt.tecnico;

import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.security.Key;
import java.security.MessageDigest;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import static javax.xml.bind.DatatypeConverter.printHexBinary;

import com.google.gson.*;

/**
 * Example of JSON writer.
 */
public class SecureWriter {

    private static final String MAC_FILENAME = "mac";

    /** Message authentication code algorithm. */
	private static final String MAC_ALGO = "HmacSHA256";

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

        // Write JSON object to file
        try (FileWriter fileWriter = new FileWriter(filename)) {
            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            gson.toJson(jsonObject, fileWriter);
        }

        
        // Add integrity protection
        // For now, use symetric criptography
        
        SecretKey key = KeyUtils.readKey("keys/secret.key");

        System.out.println(jsonObject.toString());
        
        // make MAC
		System.out.println("Signing...");
		byte[] cipherDigest = makeMAC(jsonObject.toString().getBytes(), key);
		System.out.println("CipherDigest:");
		System.out.println(printHexBinary(cipherDigest));
            
        // Append MAC to message
        try (FileWriter fileWriter = new FileWriter(MAC_FILENAME)) {
            String encodedString = Base64.getEncoder().encodeToString(cipherDigest);
            fileWriter.write(encodedString);
        }
    }
}
