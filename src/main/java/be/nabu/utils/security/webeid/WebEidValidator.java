package be.nabu.utils.security.webeid;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.Base64;
import java.util.Collections;
import java.util.Set;
import java.util.regex.Pattern;

/** Validates a structured web-eid:1.0 RS256 proof. JSON parsing and challenge lifecycle belong to the caller. */
public final class WebEidValidator {
	public static final class Token {
		public final String format;
		public final String algorithm;
		public final String unverifiedCertificate;
		public final String signature;

		public Token(String format, String algorithm, String unverifiedCertificate, String signature) {
			this.format = format;
			this.algorithm = algorithm;
			this.unverifiedCertificate = unverifiedCertificate;
			this.signature = signature;
		}
	}

	public static final class Result {
		public final X509Certificate certificate;
		public final Status ocsp;
		public final byte[] ocspResponse;

		private Result(X509Certificate certificate, Status ocsp, byte[] ocspResponse) {
			this.certificate = certificate;
			this.ocsp = ocsp;
			this.ocspResponse = ocspResponse == null ? null : ocspResponse.clone();
		}
	}

	public enum Status { GOOD, NOT_CHECKED }

	private final String origin;
	private final X509Certificate issuer;
	private final Set<String> policies;
	private final URI ocspEndpoint;
	private final WebEidOcsp.Transport transport;
	private final Clock clock;
	private final boolean checkOcsp;

	public WebEidValidator(String origin, X509Certificate issuer, Set<String> policies, URI ocspEndpoint,
			WebEidOcsp.Transport transport, Clock clock) {
		this(origin, issuer, policies, ocspEndpoint, transport, clock, true);
	}

	/** Set checkOcsp to false only under an explicit server-side offline policy. */
	public WebEidValidator(String origin, X509Certificate issuer, Set<String> policies, URI ocspEndpoint,
			WebEidOcsp.Transport transport, Clock clock, boolean checkOcsp) {
		if (origin == null || !Pattern.matches("https://[a-zA-Z0-9.-]+(:[0-9]{1,5})?", origin)
				|| issuer == null || policies == null || policies.isEmpty() || clock == null || checkOcsp && (ocspEndpoint == null || transport == null)) {
			throw new IllegalArgumentException("Invalid Web eID configuration");
		}
		URI parsed = URI.create(origin);
		if (parsed.getHost() == null || parsed.getPort() > 65535 || parsed.getPort() == 0 || !origin.equals(parsed.toASCIIString())) {
			throw new IllegalArgumentException("Invalid ASCII site origin");
		}
		this.origin = origin;
		this.issuer = issuer;
		this.policies = Collections.unmodifiableSet(new java.util.HashSet<>(policies));
		this.ocspEndpoint = ocspEndpoint;
		this.transport = transport;
		this.clock = clock;
		this.checkOcsp = checkOcsp;
	}

	public Result validate(Token token, String challenge) throws GeneralSecurityException, IOException {
		if (token == null || !"web-eid:1.0".equals(token.format) || !"RS256".equals(token.algorithm)
				|| challenge == null || challenge.length() < 44 || challenge.length() > 128
				|| token.unverifiedCertificate == null || token.unverifiedCertificate.length() > 16384
				|| token.signature == null || token.signature.length() > 8192) {
			throw new GeneralSecurityException("Unsupported or malformed Web eID token");
		}
		try {
			byte[] der = Base64.getUrlDecoder().decode(token.unverifiedCertificate);
			if (!Base64.getUrlEncoder().withoutPadding().encodeToString(der).equals(token.unverifiedCertificate)) {
				throw new GeneralSecurityException("Invalid certificate encoding");
			}
			ByteArrayInputStream input = new ByteArrayInputStream(der);
			X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(input);
			if (input.available() != 0 || !java.util.Arrays.equals(der, certificate.getEncoded())) {
				throw new GeneralSecurityException("Invalid certificate DER");
			}
			WebEidCertificates.validate(certificate, issuer, clock, true, policies);
			byte[] signatureBytes = Base64.getUrlDecoder().decode(token.signature);
			if (!Base64.getUrlEncoder().withoutPadding().encodeToString(signatureBytes).equals(token.signature)
					|| !"RSA".equals(certificate.getPublicKey().getAlgorithm())) {
				throw new GeneralSecurityException("Invalid signature encoding or key type");
			}
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] originHash = digest.digest(origin.getBytes(StandardCharsets.UTF_8));
			byte[] challengeHash = digest.digest(challenge.getBytes(StandardCharsets.UTF_8));
			Signature verifier = Signature.getInstance("SHA256withRSA");
			verifier.initVerify(certificate);
			verifier.update(originHash);
			verifier.update(challengeHash);
			if (!verifier.verify(signatureBytes)) {
				throw new GeneralSecurityException("Web eID proof signature mismatch");
			}
			byte[] evidence = checkOcsp ? WebEidOcsp.check(certificate, issuer, ocspEndpoint, transport, clock) : null;
			return new Result(certificate, checkOcsp ? Status.GOOD : Status.NOT_CHECKED, evidence);
		}
		catch (IllegalArgumentException e) {
			throw new GeneralSecurityException("Malformed Web eID encoding", e);
		}
	}
}
