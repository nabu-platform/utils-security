package be.nabu.utils.security;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import junit.framework.TestCase;

public class TestMac extends TestCase {
	public void testMac() throws InvalidKeyException, NoSuchAlgorithmException, IllegalStateException, IOException {
		String encodeMac = SecurityUtils.encodeMac("key".getBytes(Charset.forName("UTF-8")), 
			new ByteArrayInputStream("The quick brown fox jumps over the lazy dog".getBytes(Charset.forName("UTF-8"))), 
			"HmacSHA256");
		assertEquals("f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8", encodeMac);
	}
}
