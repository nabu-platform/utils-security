package be.nabu.utils.security;

import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

import javax.security.auth.x500.X500Principal;

import junit.framework.TestCase;
import be.nabu.utils.io.IOUtils;
import be.nabu.utils.io.api.CharContainer;

public class TestBCSecurityUtils extends TestCase {

	public void testPKCS10() throws NoSuchAlgorithmException, IOException {
		KeyPair pair = SecurityUtils.generateKeyPair(KeyPairType.RSA, 2048);
		X500Principal principal = SecurityUtils.createX500Principal("test", "Nabu", null, "Antwerp", "Antwerp", "BE");
		
		CharContainer actual = IOUtils.newCharContainer();
		BCSecurityUtils.encodePKCS10(BCSecurityUtils.generatePKCS10(pair, SignatureType.SHA1WITHRSA, principal), actual);
		String content = IOUtils.toString(actual);
		// the csr is different every time so can't check the actual copy
		// can check the length though
		assertEquals(980, content.length());
		
		X500Principal subject = BCSecurityUtils.getPKCS10Subject(IOUtils.wrap(content.toCharArray(), true));
		assertEquals(SecurityUtils.getParts(principal), SecurityUtils.getParts(subject));
	}
	
	
	
}
