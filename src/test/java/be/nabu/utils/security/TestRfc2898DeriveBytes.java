package be.nabu.utils.security;

import static org.junit.Assert.assertNotEquals;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import junit.framework.TestCase;

public class TestRfc2898DeriveBytes extends TestCase {
	
	// actual example as generated from a C# codebase
	public void testActualExample() throws InvalidKeyException, NoSuchAlgorithmException, IOException {
		String passwordToCheck = "024450";
		String hashToCheck = "ANh5UMKk7oBae+Ftzc9RvcPSKUEkFnPy/2UbUL05lxR5ylrG3RzSB677IkWVFYzKQw==";
		assertTrue(Rfc2898DeriveBytes.validateCryptoHash(hashToCheck, passwordToCheck));
	}
	
	public void testGeneratedExample() throws InvalidKeyException, NoSuchAlgorithmException, IOException {
		String previousHash = null;
		String password = "thisisnotasafepassword1";
		for (int i = 0; i < 10; i++) {
			String newHash = Rfc2898DeriveBytes.generateCryptoHash(password);
			if (previousHash != null) {
				assertNotEquals(previousHash, newHash);
			}
			assertTrue(Rfc2898DeriveBytes.validateCryptoHash(newHash, password));
			previousHash = newHash;
		}
	}
}
