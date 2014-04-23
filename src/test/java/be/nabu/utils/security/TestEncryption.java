package be.nabu.utils.security;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import junit.framework.TestCase;
import be.nabu.utils.codec.TranscoderUtils;
import be.nabu.utils.codec.impl.Base64Decoder;
import be.nabu.utils.codec.impl.Base64Encoder;
import be.nabu.utils.io.IOUtils;
import be.nabu.utils.io.api.ByteContainer;
import be.nabu.utils.security.api.ManagedKeyStore;
import be.nabu.utils.security.impl.SimpleManagedKeyStore;

public class TestEncryption extends TestCase {
	
	public void testEncryption() throws GeneralSecurityException, IOException {
		KeyPair pair = SecurityUtils.generateKeyPair(KeyPairType.RSA, 1024);
		X500Principal issuer = SecurityUtils.createX500Principal("test", null, null, null, "Antwerp", "Belgium");
		X509Certificate certificate = BCSecurityUtils.generateSelfSignedCertificate(pair, TestSigning.yearLong(), issuer, issuer);
		
		String content = "this is a test";
		
		// you can only test aes256 with unrestricted policy files on
		// otherwise you get an "illegal key size" exception
		ByteContainer container = IOUtils.newByteContainer();
		container = IOUtils.wrap(
			container,
			BCSecurityUtils.encrypt(container, SynchronousEncryptionAlgorithm.AES128_CBC, certificate)
		);
		container.write(content.getBytes("ASCII"));
		container.close();
		byte [] encrypted = IOUtils.toBytes(container);
	
		// decrypt it with the given key
		container = IOUtils.newByteContainer();
		// the encrypted data has to be present _before_ it is wrapped in a decryption stream
		// otherwise you get a npe likely because the decrypting wrapper reads some initial data to parse things like sender/receivers
		container.write(encrypted);
		container = IOUtils.wrap(
			BCSecurityUtils.decrypt(container, pair.getPrivate()),
			container
		);
		assertEquals(content, new String(IOUtils.toBytes(container)));
		
		// decrypt it with a keystore
		ManagedKeyStore managedStore = new SimpleManagedKeyStore();
		managedStore.set("wee", pair.getPrivate(), new X509Certificate [] { certificate }, null);
		container = IOUtils.newByteContainer();
		container.write(encrypted);
		container = IOUtils.wrap(
			BCSecurityUtils.decrypt(container, managedStore),
			container
		);
		assertEquals(content, new String(IOUtils.toBytes(container)));
	}
	
	public void testEncryptionWithBase64() throws IOException, GeneralSecurityException {
		KeyPair pair = SecurityUtils.generateKeyPair(KeyPairType.RSA, 2048);
		X500Principal issuer = SecurityUtils.createX500Principal("test", null, null, null, "Antwerp", "Belgium");
		X509Certificate certificate = BCSecurityUtils.generateSelfSignedCertificate(pair, TestSigning.yearLong(), issuer, issuer);
		
		String content = "----- slightly larger test with stuff in it---------";
		
		ByteContainer container = IOUtils.newByteContainer();
		container = IOUtils.wrap(
			container,
			BCSecurityUtils.encrypt(container, SynchronousEncryptionAlgorithm.AES128_CBC, certificate)
		);
		container.write(content.getBytes("ASCII"));
		container.close();
		byte [] encrypted = IOUtils.toBytes(container);
		byte [] encoded = IOUtils.toBytes(TranscoderUtils.wrapInput(IOUtils.wrap(encrypted), new Base64Encoder()));
		
		ManagedKeyStore managedStore = new SimpleManagedKeyStore();
		managedStore.set("wee", pair.getPrivate(), new X509Certificate [] { certificate }, "test");
		container = IOUtils.newByteContainer();
		// BCSecurityUtils.decrypt(container, managedStore)
		IOUtils.copy(BCSecurityUtils.decrypt(TranscoderUtils.wrapInput(IOUtils.wrap(encoded), new Base64Decoder()), managedStore), container);
		container.close();
		assertEquals(content, new String(IOUtils.toBytes(container)));
	}
}
