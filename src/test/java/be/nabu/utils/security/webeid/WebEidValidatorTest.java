package be.nabu.utils.security.webeid;

import static org.junit.Assert.*;

import java.math.BigInteger;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.cert.ocsp.jcajce.JcaBasicOCSPRespBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.junit.Before;
import org.junit.Test;

public class WebEidValidatorTest {
	private final BouncyCastleProvider provider = new BouncyCastleProvider();
	private final Clock clock = Clock.fixed(Instant.parse("2025-01-01T12:00:00Z"), ZoneOffset.UTC);
	private KeyPair caKey;
	private KeyPair userKey;
	private X509Certificate ca;
	private X509Certificate user;
	private String challenge;
	private final String origin = "https://example.org";

	@Before
	public void setup() throws Exception {
		caKey = key();
		userKey = key();
		ca = certificate(caKey, caKey, "CN=CA", "CN=CA", true, true, true, -1);
		user = certificate(userKey, caKey, "CN=CA", "CN=User", false, true, true, -1);
		challenge = Base64.getUrlEncoder().encodeToString(new byte[32]);
	}

	private KeyPair key() throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(2048);
		return generator.generateKeyPair();
	}

	private X509Certificate certificate(KeyPair keys, KeyPair signer, String issuer, String subject,
			boolean caCert, boolean purpose, boolean policy, int expiryDays) throws Exception {
		return certificate(keys, signer, issuer, subject, caCert, purpose, policy, expiryDays,
				purpose && !caCert ? KeyPurposeId.id_kp_clientAuth : null);
	}

	private X509Certificate certificate(KeyPair keys, KeyPair signer, String issuer, String subject,
			boolean caCert, boolean purpose, boolean policy, int expiryDays, KeyPurposeId eku) throws Exception {
		Date start = Date.from(clock.instant().minusSeconds(86400));
		Date end = Date.from(clock.instant().plusSeconds(expiryDays < 0 ? 86400 : (expiryDays == 0 ? -3600L : expiryDays * 86400L)));
		X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(new X500Name(issuer),
				BigInteger.valueOf(Math.abs(subject.hashCode()) + 1L), start, end, new X500Name(subject), keys.getPublic());
		builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(caCert));
		builder.addExtension(Extension.keyUsage, true, new KeyUsage(caCert ? KeyUsage.keyCertSign : purpose ? KeyUsage.digitalSignature : KeyUsage.keyEncipherment));
		if (!caCert && eku != null) {
			builder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(eku));
		}
		if (!caCert && policy) {
			builder.addExtension(Extension.certificatePolicies, false,
					new CertificatePolicies(new PolicyInformation(new ASN1ObjectIdentifier("1.2.3.4"))));
		}
		return new JcaX509CertificateConverter().setProvider(provider).getCertificate(builder.build(
				new JcaContentSignerBuilder("SHA256withRSA").setProvider(provider).build(signer.getPrivate())));
	}

	private WebEidValidator validator(X509Certificate anchor, boolean online, WebEidOcsp.Transport transport) {
		return new WebEidValidator(origin, anchor, Collections.singleton("1.2.3.4"), URI.create("https://ocsp.example.org"), transport, clock, online);
	}

	private WebEidValidator.Token token(X509Certificate cert, KeyPair signer, String signedOrigin, String signedChallenge) throws Exception {
		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		Signature signature = Signature.getInstance("SHA256withRSA");
		signature.initSign(signer.getPrivate());
		signature.update(digest.digest(signedOrigin.getBytes(StandardCharsets.UTF_8)));
		signature.update(digest.digest(signedChallenge.getBytes(StandardCharsets.UTF_8)));
		return new WebEidValidator.Token("web-eid:1.0", "RS256", Base64.getUrlEncoder().withoutPadding().encodeToString(cert.getEncoded()),
				Base64.getUrlEncoder().withoutPadding().encodeToString(signature.sign()));
	}

	private void rejected(WebEidValidator validator, WebEidValidator.Token token) throws Exception {
		try {
			validator.validate(token, challenge);
			fail("Expected rejection");
		}
		catch (java.security.GeneralSecurityException | java.io.IOException expected) {
			assertNotNull(expected.getMessage());
		}
	}

	@Test
	public void offlineAndProofFailures() throws Exception {
		WebEidValidator offline = validator(ca, false, null);
		assertEquals(WebEidValidator.Status.NOT_CHECKED, offline.validate(token(user, userKey, origin, challenge), challenge).ocsp);
		rejected(offline, token(user, userKey, "https://other.org", challenge));
		rejected(offline, token(user, userKey, origin, Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[] {1, 2, 3})));
		rejected(offline, token(user, key(), origin, challenge));
		WebEidValidator.Token valid = token(user, userKey, origin, challenge);
		rejected(offline, new WebEidValidator.Token("web-eid:2.0", "RS256", valid.unverifiedCertificate, valid.signature));
		rejected(offline, new WebEidValidator.Token("web-eid:1.0", "PS256", valid.unverifiedCertificate, valid.signature));
		rejected(offline, new WebEidValidator.Token(valid.format, valid.algorithm, valid.unverifiedCertificate + "=", valid.signature));
	}

	@Test
	public void trustValidityPurposeAndPolicy() throws Exception {
		rejected(validator(certificate(key(), key(), "CN=Other", "CN=Other", true, true, true, -1), false, null), token(user, userKey, origin, challenge));
		rejected(validator(ca, false, null), token(certificate(userKey, caKey, "CN=CA", "CN=Expired", false, true, true, 0), userKey, origin, challenge));
		rejected(validator(ca, false, null), token(certificate(userKey, caKey, "CN=CA", "CN=WrongUse", false, false, true, -1), userKey, origin, challenge));
		rejected(validator(ca, false, null), token(certificate(userKey, caKey, "CN=CA", "CN=NoPolicy", false, true, false, -1), userKey, origin, challenge));
	}

	private byte[] response(byte[] requestBytes, CertificateStatus status, boolean wrongCert, boolean stale, boolean wrongNonce, boolean forged) throws Exception {
		return response(requestBytes, status, wrongCert, stale, wrongNonce, forged, false, false, null, null);
	}

	private byte[] response(byte[] requestBytes, CertificateStatus status, boolean wrongCert, boolean stale, boolean wrongNonce,
			boolean forged, boolean missingNonce, boolean future, X509Certificate responder, KeyPair responderKey) throws Exception {
		OCSPReq request = new OCSPReq(requestBytes);
		CertificateID id = request.getRequestList()[0].getCertID();
		if (wrongCert) {
			id = new CertificateID(new org.bouncycastle.asn1.ocsp.CertID(id.toASN1Primitive().getHashAlgorithm(), new DEROctetString(id.getIssuerNameHash()), new DEROctetString(id.getIssuerKeyHash()), new org.bouncycastle.asn1.ASN1Integer(id.getSerialNumber().add(BigInteger.ONE))));
		}
		BasicOCSPRespBuilder builder = new JcaBasicOCSPRespBuilder(responder == null ? caKey.getPublic() : responderKey.getPublic(),
				new org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder().setProvider(provider).build().get(CertificateID.HASH_SHA1));
		Date now = Date.from(clock.instant());
		builder.addResponse(id, status, new Date(now.getTime() + (future ? 3600000 : stale ? -7200000 : -60000)), new Date(now.getTime() + (future ? 7200000 : 60000)), null);
		ExtensionsGenerator extensions = new ExtensionsGenerator();
		byte[] nonce = ASN1OctetString.getInstance(request.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce).getParsedValue()).getOctets();
		if (wrongNonce) {
			nonce[0] ^= 1;
		}
		if (!missingNonce) {
			extensions.addExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString(nonce));
			builder.setResponseExtensions(extensions.generate());
		}
		return new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, builder.build(
				new JcaContentSignerBuilder("SHA256withRSA").setProvider(provider).build((forged ? key() : responderKey == null ? caKey : responderKey).getPrivate()),
				responder == null ? new org.bouncycastle.cert.X509CertificateHolder[0] : new org.bouncycastle.cert.X509CertificateHolder[] {
					new org.bouncycastle.cert.jcajce.JcaX509CertificateHolder(responder) }, now)).getEncoded();
	}

	private void checkOcsp(CertificateStatus status, boolean wrongCert, boolean stale, boolean wrongNonce, boolean forged,
			boolean missingNonce, boolean future, X509Certificate responder, KeyPair responderKey, boolean accepted) throws Exception {
		WebEidValidator validator = validator(ca, true, (uri, request) -> {
			try {
				return response(request, status, wrongCert, stale, wrongNonce, forged, missingNonce, future, responder, responderKey);
			}
			catch (Exception e) {
				throw new java.io.IOException(e);
			}
		});
		WebEidValidator.Token valid = token(user, userKey, origin, challenge);
		if (accepted) {
			assertEquals(WebEidValidator.Status.GOOD, validator.validate(valid, challenge).ocsp);
		}
		else {
			rejected(validator, valid);
		}
	}

	@Test public void paddedChallenge() throws Exception {
		assertEquals(WebEidValidator.Status.NOT_CHECKED, validator(ca, false, null).validate(token(user, userKey, origin, challenge), challenge).ocsp);
	}
	@Test public void opaqueChallenge() throws Exception {
		challenge = "opaque!challenge with spaces and +/= symbols 12345";
		assertEquals(WebEidValidator.Status.NOT_CHECKED, validator(ca, false, null).validate(token(user, userKey, origin, challenge), challenge).ocsp);
	}
	@Test public void minimumChallenge() throws Exception {
		challenge = String.join("", Collections.nCopies(44, "x"));
		assertNotNull(validator(ca, false, null).validate(token(user, userKey, origin, challenge), challenge));
	}
	@Test public void maximumChallenge() throws Exception {
		challenge = String.join("", Collections.nCopies(128, "x"));
		assertNotNull(validator(ca, false, null).validate(token(user, userKey, origin, challenge), challenge));
	}
	@Test public void shortChallenge() throws Exception {
		challenge = String.join("", Collections.nCopies(43, "x"));
		rejected(validator(ca, false, null), token(user, userKey, origin, challenge));
	}
	@Test public void longChallenge() throws Exception {
		challenge = String.join("", Collections.nCopies(129, "x"));
		rejected(validator(ca, false, null), token(user, userKey, origin, challenge));
	}
	@Test public void exactChallengeBinding() throws Exception {
		WebEidValidator.Token signed = token(user, userKey, origin, challenge);
		challenge = challenge.substring(0, 43) + "A";
		rejected(validator(ca, false, null), signed);
	}
	@Test public void wrongOrigin() throws Exception { rejected(validator(ca, false, null), token(user, userKey, "https://other.org", challenge)); }
	@Test public void wrongSignature() throws Exception { rejected(validator(ca, false, null), token(user, key(), origin, challenge)); }
	@Test public void untrustedCertificate() throws Exception {
		rejected(validator(certificate(key(), key(), "CN=Other", "CN=Other", true, true, true, -1), false, null), token(user, userKey, origin, challenge));
	}
	@Test public void expiredCertificate() throws Exception {
		rejected(validator(ca, false, null), token(certificate(userKey, caKey, "CN=CA", "CN=Expired", false, true, true, 0), userKey, origin, challenge));
	}
	@Test public void invalidPurpose() throws Exception {
		rejected(validator(ca, false, null), token(certificate(userKey, caKey, "CN=CA", "CN=WrongUse", false, false, true, -1), userKey, origin, challenge));
	}
	@Test public void defaultOcspEnabled() throws Exception {
		try {
			new WebEidValidator(origin, ca, Collections.singleton("1.2.3.4"), null, null, clock);
			fail("OCSP must be configured by default");
		}
		catch (IllegalArgumentException expected) {
			assertNotNull(expected.getMessage());
		}
	}
	@Test public void offlineNotChecked() throws Exception {
		assertEquals(WebEidValidator.Status.NOT_CHECKED, validator(ca, false, null).validate(token(user, userKey, origin, challenge), challenge).ocsp);
	}
	@Test public void revokedOcsp() throws Exception { checkOcsp(new RevokedStatus(Date.from(clock.instant()), 0), false, false, false, false, false, false, null, null, false); }
	@Test public void unknownOcsp() throws Exception { checkOcsp(new UnknownStatus(), false, false, false, false, false, false, null, null, false); }
	@Test public void staleOcsp() throws Exception { checkOcsp(CertificateStatus.GOOD, false, true, false, false, false, false, null, null, false); }
	@Test public void futureOcsp() throws Exception { checkOcsp(CertificateStatus.GOOD, false, false, false, false, false, true, null, null, false); }
	@Test public void missingNonce() throws Exception { checkOcsp(CertificateStatus.GOOD, false, false, false, false, true, false, null, null, false); }
	@Test public void mismatchedNonce() throws Exception { checkOcsp(CertificateStatus.GOOD, false, false, true, false, false, false, null, null, false); }
	@Test public void wrongOcspCertificate() throws Exception { checkOcsp(CertificateStatus.GOOD, true, false, false, false, false, false, null, null, false); }
	@Test public void forgedOcspSignature() throws Exception { checkOcsp(CertificateStatus.GOOD, false, false, false, true, false, false, null, null, false); }
	@Test public void transportFailure() throws Exception {
		rejected(validator(ca, true, (uri, request) -> { throw new java.io.IOException("transport failure"); }), token(user, userKey, origin, challenge));
	}
	@Test public void delegatedResponder() throws Exception {
		KeyPair keys = key();
		X509Certificate responder = certificate(keys, caKey, "CN=CA", "CN=Responder", false, true, false, -1, KeyPurposeId.id_kp_OCSPSigning);
		checkOcsp(CertificateStatus.GOOD, false, false, false, false, false, false, responder, keys, true);
	}
	@Test public void unauthorizedResponder() throws Exception {
		KeyPair keys = key();
		X509Certificate responder = certificate(keys, key(), "CN=Other", "CN=Responder", false, true, false, -1, KeyPurposeId.id_kp_OCSPSigning);
		checkOcsp(CertificateStatus.GOOD, false, false, false, false, false, false, responder, keys, false);
	}
	@Test public void responderWithoutEku() throws Exception {
		KeyPair keys = key();
		X509Certificate responder = certificate(keys, caKey, "CN=CA", "CN=Responder", false, true, false, -1, null);
		checkOcsp(CertificateStatus.GOOD, false, false, false, false, false, false, responder, keys, false);
	}
	@Test public void invalidDelegatedSignature() throws Exception {
		KeyPair keys = key();
		X509Certificate responder = certificate(keys, caKey, "CN=CA", "CN=Responder", false, true, false, -1, KeyPurposeId.id_kp_OCSPSigning);
		checkOcsp(CertificateStatus.GOOD, false, false, false, true, false, false, responder, keys, false);
	}

	@Test
	public void ocspChecks() throws Exception {
		WebEidValidator.Token valid = token(user, userKey, origin, challenge);
		assertEquals(WebEidValidator.Status.GOOD, validator(ca, true, (uri, request) -> {
			try { return response(request, CertificateStatus.GOOD, false, false, false, false); }
			catch (Exception e) { throw new java.io.IOException(e); }
		}).validate(valid, challenge).ocsp);
		for (int scenario = 0; scenario < 7; scenario++) {
			final int n = scenario;
			rejected(validator(ca, true, (uri, request) -> {
				if (n == 6) { throw new java.io.IOException("transport failure"); }
				try {
					return response(request, n == 0 ? new RevokedStatus(Date.from(clock.instant()), 0) : n == 1 ? new UnknownStatus() : CertificateStatus.GOOD,
						n == 4, n == 2, n == 3, n == 5);
				}
				catch (Exception e) { throw new java.io.IOException(e); }
			}), valid);
		}
	}
}
