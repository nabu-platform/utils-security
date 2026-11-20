package be.nabu.utils.security.webeid;

import java.security.GeneralSecurityException;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Set;

/** Validation restricted to directly issuing, explicitly configured CA anchors. */
public final class WebEidCertificates {
	private WebEidCertificates() {
	}

	public static void validate(X509Certificate certificate, X509Certificate issuer, Clock clock,
			boolean authenticationPurpose, Set<String> allowedPolicies) throws GeneralSecurityException {
		if (certificate == null || issuer == null || clock == null || authenticationPurpose && (allowedPolicies == null || allowedPolicies.isEmpty())) {
			throw new GeneralSecurityException("Certificate, issuer, clock and allowed policies are required");
		}
		Date now = Date.from(clock.instant());
		certificate.checkValidity(now);
		issuer.checkValidity(now);
		if (issuer.getBasicConstraints() < 0 || issuer.getKeyUsage() == null || issuer.getKeyUsage().length <= 5 || !issuer.getKeyUsage()[5]
				|| !certificate.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())) {
			throw new GeneralSecurityException("Invalid direct certificate issuer");
		}
		PKIXParameters parameters = new PKIXParameters(Collections.singleton(new TrustAnchor(issuer, null)));
		parameters.setRevocationEnabled(false); // OCSP is checked separately, never silently delegated to JVM defaults.
		parameters.setDate(now);
		CertPathValidator.getInstance("PKIX").validate(CertificateFactory.getInstance("X.509")
				.generateCertPath(Collections.singletonList(certificate)), parameters);
		boolean[] usage = certificate.getKeyUsage();
		if (usage == null || usage.length == 0 || !usage[0] || certificate.getBasicConstraints() != -1) {
			throw new GeneralSecurityException("Certificate is not a signing end entity");
		}
		if (authenticationPurpose) {
			if (certificate.getExtendedKeyUsage() == null || !certificate.getExtendedKeyUsage().contains("1.3.6.1.5.5.7.3.2")) {
				throw new GeneralSecurityException("Client authentication EKU required");
			}
		}
		else if (certificate.getExtendedKeyUsage() == null || !certificate.getExtendedKeyUsage().contains("1.3.6.1.5.5.7.3.9")) {
			throw new GeneralSecurityException("OCSP signing EKU required");
		}
		if (!authenticationPurpose) {
			return;
		}
		byte[] extension = certificate.getExtensionValue("2.5.29.32");
		if (extension == null) {
			throw new GeneralSecurityException("Certificate policies required");
		}
		try {
			org.bouncycastle.asn1.x509.CertificatePolicies policies = org.bouncycastle.asn1.x509.CertificatePolicies.getInstance(
					org.bouncycastle.asn1.ASN1Primitive.fromByteArray(org.bouncycastle.asn1.ASN1OctetString.getInstance(extension).getOctets()));
			boolean accepted = Arrays.stream(policies.getPolicyInformation()).anyMatch(policy -> allowedPolicies.contains(policy.getPolicyIdentifier().getId()));
			if (!accepted) {
				throw new GeneralSecurityException("Certificate policy not allowed");
			}
		}
		catch (IllegalArgumentException | java.io.IOException e) {
			throw new GeneralSecurityException("Invalid certificate policy extension", e);
		}
	}
}
