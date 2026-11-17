package be.nabu.utils.security;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.KeyPairGenerator;
import java.security.spec.InvalidKeySpecException;

import org.junit.Test;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;

public class TestEcSignatures {
	@Test
	public void testEs256SpkiVerification() throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
		generator.initialize(new ECGenParameterSpec("secp256r1"));
		KeyPair pair = generator.generateKeyPair();
		KeyPair other = generator.generateKeyPair();
		byte[] data = "signed content".getBytes(StandardCharsets.UTF_8);
		Signature signer = Signature.getInstance("SHA256withECDSA");
		signer.initSign(pair.getPrivate());
		signer.update(data);
		byte[] signature = signer.sign();

		assertTrue(SecurityUtils.verify(new ByteArrayInputStream(data), signature,
			SecurityUtils.parsePublic(KeyPairType.EC, pair.getPublic().getEncoded()), SignatureType.SHA256WITHECDSA));
		assertFalse(SecurityUtils.verify(new ByteArrayInputStream("tampered content".getBytes(StandardCharsets.UTF_8)), signature,
			SecurityUtils.parsePublic(KeyPairType.EC, pair.getPublic().getEncoded()), SignatureType.SHA256WITHECDSA));
		assertFalse(SecurityUtils.verify(new ByteArrayInputStream(data), signature,
			SecurityUtils.parsePublic(KeyPairType.EC, other.getPublic().getEncoded()), SignatureType.SHA256WITHECDSA));
	}

	@Test(expected = InvalidKeySpecException.class)
	public void testMalformedSpki() throws Exception {
		SecurityUtils.parsePublic(KeyPairType.EC, new byte[] { 1, 2, 3 });
	}
}
