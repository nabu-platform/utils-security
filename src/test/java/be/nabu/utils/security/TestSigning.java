package be.nabu.utils.security;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import junit.framework.TestCase;
import be.nabu.utils.io.IOUtils;
import be.nabu.utils.io.api.ByteContainer;
import be.nabu.utils.io.api.ReadableByteContainer;

public class TestSigning extends TestCase {
	
	public void testSelfSign() throws GeneralSecurityException, IOException {
		KeyPair pair = SecurityUtils.generateKeyPair(KeyPairType.RSA, 1024);
		X500Principal issuer = SecurityUtils.createX500Principal("test", null, null, null, "Antwerp", "Belgium");
		X509Certificate certificate = BCSecurityUtils.generateSelfSignedCertificate(pair, yearLong(), issuer, issuer);
		
		String data = "MIME-Version: 1.0\r\nContent-Type: text/plain;\r\n\r\nthis is a test";
		ByteContainer container = IOUtils.newByteContainer();
		container = IOUtils.wrap(
			container,
			BCSecurityUtils.sign(container, BCSecurityUtils.createSignerStore(
				BCSecurityUtils.createSigner(pair.getPrivate(), certificate, SignatureType.SHA1WITHRSA)
			), false)
		);
		container.write(data.getBytes("ASCII"));
		container.close();
		
		// this contains the signature(s) of the data
		byte [] signatures = IOUtils.toBytes(container);
		
		assertNotNull(BCSecurityUtils.verify(
				IOUtils.wrap(data.getBytes("ASCII"), true), 
				IOUtils.wrap(signatures, true), 
				BCSecurityUtils.createCertificateStore(new X509Certificate[] { certificate }), 
				certificate));
	}
	
	public void testSign() throws IOException, GeneralSecurityException {
		X500Principal issuer = SecurityUtils.createX500Principal("testCA", null, null, null, "Antwerp", "Belgium");
		// ca
		KeyPair caPair = SecurityUtils.generateKeyPair(KeyPairType.RSA, 1024);
		X509Certificate ca = BCSecurityUtils.generateSelfSignedCertificate(caPair, yearLong(), issuer, issuer);
		// user
		X500Principal subject = SecurityUtils.createX500Principal("testUser", null, null, null, "Antwerp", "Belgium");
		KeyPair userPair = SecurityUtils.generateKeyPair(KeyPairType.RSA, 1024);
		ReadableByteContainer csr = BCSecurityUtils.generatePKCS10(userPair, SignatureType.SHA1WITHRSA, subject);
		// sign user with ca
		X509Certificate user = BCSecurityUtils.signPKCS10(csr, yearLong(), issuer, caPair.getPrivate());
		
		String data = "this is my data that serves as a test of signature generation and verification";
		ByteContainer container = IOUtils.newByteContainer();
		
		container = IOUtils.wrap(
			container,
			BCSecurityUtils.sign(container, BCSecurityUtils.createSignerStore(
				BCSecurityUtils.createSigner(userPair.getPrivate(), user, SignatureType.SHA1WITHRSA)
			), false)
		);
		container.write(data.getBytes("ASCII"));
		container.close();
		
		// this contains the signature(s) of the data
		byte [] signatures = IOUtils.toBytes(container);
		
		assertNotNull(BCSecurityUtils.verify(
				IOUtils.wrap(data.getBytes("ASCII"), true), 
				IOUtils.wrap(signatures, true), 
				BCSecurityUtils.createCertificateStore(new X509Certificate[] { user }), 
				ca));
	}
	
	public void testEnclosedSelfSigned() throws GeneralSecurityException, IOException {
		KeyPair pair = SecurityUtils.generateKeyPair(KeyPairType.RSA, 1024);
		X500Principal issuer = SecurityUtils.createX500Principal("test", null, null, null, "Antwerp", "Belgium");
		X509Certificate certificate = BCSecurityUtils.generateSelfSignedCertificate(pair, yearLong(), issuer, issuer);
		
		String data = "MIME-Version: 1.0\r\nContent-Type: text/plain;\r\n\r\nthis is a test";
		ByteContainer container = IOUtils.newByteContainer();
		container = IOUtils.wrap(
			container,
			BCSecurityUtils.sign(container, BCSecurityUtils.createSignerStore(
				BCSecurityUtils.createSigner(pair.getPrivate(), certificate, SignatureType.SHA1WITHRSA)
			), true)
		);
		container.write(data.getBytes("ASCII"));
		container.close();
		
		// this now contains the signed data
		byte [] signedData = IOUtils.toBytes(container);
		
		assertNotNull(BCSecurityUtils.verify(
				IOUtils.wrap(signedData, true), 
				BCSecurityUtils.createCertificateStore(new X509Certificate[] { certificate }), 
				certificate));
	}
	
	public static Date yearLong() {
		return new Date(new Date().getTime() + 1000*60*60*24*365);
	}

	
}
