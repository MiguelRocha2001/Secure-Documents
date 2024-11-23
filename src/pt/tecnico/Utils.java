package pt.tecnico;

import java.io.FileInputStream;
import java.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import static javax.xml.bind.DatatypeConverter.printHexBinary;

public class Utils {
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

	public static byte[] concatWithArrayCopy(byte[] array1, byte[] array2) {
        byte[] result = Arrays.copyOf(array1, array1.length + array2.length);
        System.arraycopy(array2, 0, result, array1.length, array2.length);
        return result;
    }
}
