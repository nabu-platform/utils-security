package be.nabu.utils.security;

import static be.nabu.utils.io.IOUtils.*;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import junit.framework.TestCase;
import be.nabu.utils.codec.TranscoderUtils;
import be.nabu.utils.codec.impl.Base64Decoder;
import be.nabu.utils.codec.impl.Base64Encoder;
import be.nabu.utils.io.api.ByteBuffer;
import be.nabu.utils.io.api.Container;
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
		Container<ByteBuffer> container = newByteBuffer();
		container = wrap(
			container,
			wrap(BCSecurityUtils.encrypt(toOutputStream(container), SynchronousEncryptionAlgorithm.AES128_CBC, certificate))
		);
		container.write(wrap(content.getBytes("ASCII"), true));
		container.close();
		byte [] encrypted = toBytes(container);
	
		// decrypt it with the given key
		container = newByteBuffer();
		// the encrypted data has to be present _before_ it is wrapped in a decryption stream
		// otherwise you get a npe likely because the decrypting wrapper reads some initial data to parse things like sender/receivers
		container.write(wrap(encrypted, true));
		container = wrap(
			wrap(BCSecurityUtils.decrypt(toInputStream(container), pair.getPrivate())),
			container
		);
		assertEquals(content, new String(toBytes(container)));
		
		// decrypt it with a keystore
		ManagedKeyStore managedStore = new SimpleManagedKeyStore();
		managedStore.set("wee", pair.getPrivate(), new X509Certificate [] { certificate }, null);
		container = newByteBuffer();
		container.write(wrap(encrypted, true));
		container = wrap(
			wrap(BCSecurityUtils.decrypt(toInputStream(container), managedStore)),
			container
		);
		assertEquals(content, new String(toBytes(container)));
	}
	
	public void testEncryptionWithBase64() throws IOException, GeneralSecurityException {
		KeyPair pair = SecurityUtils.generateKeyPair(KeyPairType.RSA, 2048);
		X500Principal issuer = SecurityUtils.createX500Principal("test", null, null, null, "Antwerp", "Belgium");
		X509Certificate certificate = BCSecurityUtils.generateSelfSignedCertificate(pair, TestSigning.yearLong(), issuer, issuer);
		
		String content = "----- slightly larger test with stuff in it---------";
		
		Container<ByteBuffer> container = newByteBuffer();
		container = wrap(
			container,
			wrap(BCSecurityUtils.encrypt(toOutputStream(container), SynchronousEncryptionAlgorithm.AES128_CBC, certificate))
		);
		container.write(wrap(content.getBytes("ASCII"), true));
		container.close();
		byte [] encrypted = toBytes(container);
		byte [] encoded = toBytes(TranscoderUtils.wrapReadable(wrap(encrypted, true), new Base64Encoder()));
		
		ManagedKeyStore managedStore = new SimpleManagedKeyStore();
		managedStore.set("wee", pair.getPrivate(), new X509Certificate [] { certificate }, "test");
		container = newByteBuffer();
		// BCSecurityUtils.decrypt(container, managedStore)
		copyBytes(
			wrap(
				BCSecurityUtils.decrypt(
					toInputStream(TranscoderUtils.wrapReadable(wrap(encoded, true), new Base64Decoder())),
					managedStore
				)
			), 
			container
		);		
		container.close();
		assertEquals(content, new String(toBytes(container)));
	}
}
