package pt.tecnico;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.SecretKey;

import static javax.xml.bind.DatatypeConverter.printHexBinary;

public class SecureReader {

    private static final String MAC_FILENAME = "mac";

    /** Message authentication code algorithm. */
	private static final String MAC_ALGO = "HmacSHA256";

    /**
	 * Calculates new digest from text and compare it to the to deciphered digest.
	 */
	private static boolean verifyMAC(byte[] receivedMacBytes, byte[] bytes, SecretKey key) throws Exception {
		Mac mac = Mac.getInstance(MAC_ALGO);
		mac.init(key);
		byte[] recomputedMacBytes = mac.doFinal(bytes);

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

        // Read JSON object from file, and print its contets
        try (FileReader fileReader = new FileReader(filename)) {
            Gson gson = new Gson();
            JsonObject rootJson = gson.fromJson(fileReader, JsonObject.class);
            //System.out.println("JSON object: " + rootJson);

            JsonObject headerObject = rootJson.get("header").getAsJsonObject();
            System.out.println("Document header:");
            System.out.println("Author: " + headerObject.get("author").getAsString());
            System.out.println("Version: " + headerObject.get("version").getAsInt());
            System.out.println("Title: " + headerObject.get("title").getAsString());

            JsonArray tagsArray = headerObject.getAsJsonArray("tags");
            System.out.print("Tags: ");
            for (int i = 0; i < tagsArray.size(); i++) {
                System.out.print(tagsArray.get(i).getAsString());
                if (i < tagsArray.size() - 1) {
                    System.out.print(", ");
                } else {
                    System.out.println(); // Print a newline after the final tag
                }
            }

            System.out.println("Document body: " + rootJson.get("body").getAsString());

            System.out.println("Document status: " + rootJson.get("status").getAsString());
            
            Path path = Paths.get(MAC_FILENAME);
            
            byte[] encodedMac = Files.readAllBytes(path);
            byte[] mac = Base64.getDecoder().decode(encodedMac);
            
            System.out.println("CipherDigest:");
            System.out.println(printHexBinary(mac));
            
            byte[] plainBytes = rootJson.toString().getBytes();
            System.out.println(rootJson.toString());
            
            SecretKey key = KeyUtils.readKey("keys/secret.key");
            
            // verify the MAC
            System.out.println("Verifying...");
            boolean result = verifyMAC(mac, plainBytes, key);
            System.out.println("MAC is " + (result ? "right" : "wrong"));
        }
    }
}
