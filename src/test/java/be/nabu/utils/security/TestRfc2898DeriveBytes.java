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
		
		assertTrue(Rfc2898DeriveBytes.validateCryptoHash("AJwgdfzRCmGE6kSKK1zF5sc7aLJ1noCLJmPQEYKOVt0eciCs3Zn8tT15luhXkMBGqQ==", "450803"));
		assertTrue(Rfc2898DeriveBytes.validateCryptoHash("AJWcXL5CFl7fQQ2rBcppXfWJR+P9gBNZjHow44HYcZfcQDyC35djXwYpTnmHInyzXA==", "573720"));
		assertTrue(Rfc2898DeriveBytes.validateCryptoHash("ABzu2/DkMD0RXbQVqyFrIeFIUtNpsEO/vmEi3tP4Ew1rRqOBps+KgoN7bbPV1hdR6Q==", "619271"));
		assertTrue(Rfc2898DeriveBytes.validateCryptoHash("AH6o+kSPz0tGjTTBFEN5L1b11PKHRDnxJTG6XfrX55qzPMoLDLaZf+0dEnNJB1JZFA==", "195818"));
		
		// some incorrect combinations
		assertFalse(Rfc2898DeriveBytes.validateCryptoHash("AH6o+kSPz0tGjTTBFEN5L1b11PKHRDnxJTG6XfrX55qzPMoLDLaZf+0dEnNJB1JZFA==", "619271"));
		assertFalse(Rfc2898DeriveBytes.validateCryptoHash("ABzu2/DkMD0RXbQVqyFrIeFIUtNpsEO/vmEi3tP4Ew1rRqOBps+KgoN7bbPV1hdR6Q==", "195818"));
		assertFalse(Rfc2898DeriveBytes.validateCryptoHash("AJwgdfzRCmGE6kSKK1zF5sc7aLJ1noCLJmPQEYKOVt0eciCs3Zn8tT15luhXkMBGqQ==", "573720"));
		assertFalse(Rfc2898DeriveBytes.validateCryptoHash("AJWcXL5CFl7fQQ2rBcppXfWJR+P9gBNZjHow44HYcZfcQDyC35djXwYpTnmHInyzXA==", "450803"));
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
