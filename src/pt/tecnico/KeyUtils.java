package pt.tecnico;

import java.io.FileInputStream;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import static javax.xml.bind.DatatypeConverter.printHexBinary;

public class KeyUtils {
    /** Symmetric cryptography algorithm. */
	private static final String SYM_ALGO = "AES";

    public static SecretKey readKey(String keyPath) throws Exception {
		System.out.println("Reading key from file " + keyPath + " ...");
		FileInputStream fis = new FileInputStream(keyPath);
		byte[] encoded = new byte[fis.available()];
		fis.read(encoded);
		fis.close();
		//System.out.println("Key:");
		//System.out.println(printHexBinary(encoded));

		SecretKeySpec keySpec = new SecretKeySpec(encoded, SYM_ALGO);

		return keySpec;
	}
}
