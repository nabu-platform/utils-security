package be.nabu.utils.security;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import junit.framework.TestCase;

public class TestPBEEncrypt extends TestCase {

	public void testPbeDES() throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidParameterSpecException, UnsupportedEncodingException, IOException {
		String text = "test";
		String pbeEncrypt = SecurityUtils.pbeEncrypt(text.getBytes("UTF-8"), text, PBEAlgorithm.DES);
		byte[] pbeDecrypt = SecurityUtils.pbeDecrypt(pbeEncrypt, text, PBEAlgorithm.DES);
		assertEquals(text, new String(pbeDecrypt, "UTF-8"));
	}
	
	public void testPbeAES() throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidParameterSpecException, UnsupportedEncodingException, IOException {
		String text = "testing the aes version as well to see if it matches the things that i would expect";
		String pbeEncrypt = SecurityUtils.pbeEncrypt(text.getBytes("UTF-8"), "test", PBEAlgorithm.AES128);
		byte[] pbeDecrypt = SecurityUtils.pbeDecrypt(pbeEncrypt, "test", PBEAlgorithm.AES128);
		assertEquals(text, new String(pbeDecrypt, "UTF-8"));
	}
}
