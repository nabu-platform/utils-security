package be.nabu.utils.security.webeid;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.Arrays;
import java.util.Date;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/** OCSP with a mandatory nonce and a pinned direct issuer. No AIA URL discovery. */
public final class WebEidOcsp {
	public interface Transport {
		byte[] post(URI endpoint, byte[] request) throws IOException;
	}

	public static final class HttpTransport implements Transport {
		@Override
		public byte[] post(URI endpoint, byte[] request) throws IOException {
			HttpURLConnection connection = (HttpURLConnection) endpoint.toURL().openConnection();
			connection.setConnectTimeout(5000);
			connection.setReadTimeout(5000);
			connection.setInstanceFollowRedirects(false);
			connection.setDoOutput(true);
			connection.setRequestMethod("POST");
			connection.setRequestProperty("Content-Type", "application/ocsp-request");
			connection.setFixedLengthStreamingMode(request.length);
			try {
				try (OutputStream output = connection.getOutputStream()) {
					output.write(request);
				}
				if (connection.getResponseCode() != 200) {
					throw new IOException("OCSP HTTP status " + connection.getResponseCode());
				}
				try (InputStream input = connection.getInputStream(); ByteArrayOutputStream output = new ByteArrayOutputStream()) {
					byte[] buffer = new byte[4096];
					int count;
					while ((count = input.read(buffer)) != -1) {
						if (output.size() + count > 65536) {
							throw new IOException("OCSP response too large");
						}
						output.write(buffer, 0, count);
					}
					return output.toByteArray();
				}
			}
			finally {
				connection.disconnect();
			}
		}
	}

	private WebEidOcsp() {
	}

	public static byte[] check(X509Certificate certificate, X509Certificate issuer, URI endpoint,
			Transport transport, Clock clock) throws GeneralSecurityException, IOException {
		if (endpoint == null || endpoint.getHost() == null || endpoint.getUserInfo() != null || endpoint.getFragment() != null
				|| endpoint.getPort() > 65535 || endpoint.getPort() == 0 || endpoint.getRawQuery() != null
				|| !("http".equals(endpoint.getScheme()) || "https".equals(endpoint.getScheme()))
				|| transport == null || clock == null) {
			throw new GeneralSecurityException("Invalid OCSP configuration");
		}
		try {
			BouncyCastleProvider provider = new BouncyCastleProvider();
			CertificateID id = new JcaCertificateID(new org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder()
					.setProvider(provider).build().get(CertificateID.HASH_SHA1), issuer, certificate.getSerialNumber());
			byte[] nonce = new byte[32];
			new SecureRandom().nextBytes(nonce);
			ExtensionsGenerator extensions = new ExtensionsGenerator();
			extensions.addExtension(org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString(nonce));
			OCSPReqBuilder builder = new OCSPReqBuilder();
			builder.addRequest(id);
			builder.setRequestExtensions(extensions.generate());
			OCSPReq request = builder.build();
			byte[] responseBytes = transport.post(endpoint, request.getEncoded());
			if (responseBytes == null || responseBytes.length > 65536) {
				throw new GeneralSecurityException("Invalid OCSP response size");
			}
			if (!Arrays.equals(responseBytes, new OCSPResp(responseBytes).getEncoded())) {
				throw new GeneralSecurityException("Noncanonical OCSP response");
			}
			OCSPResp response = new OCSPResp(responseBytes);
			if (response.getStatus() != OCSPResp.SUCCESSFUL || !(response.getResponseObject() instanceof BasicOCSPResp)) {
				throw new GeneralSecurityException("OCSP unsuccessful");
			}
			BasicOCSPResp basic = (BasicOCSPResp) response.getResponseObject();
			Extension nonceExtension = basic.getExtension(org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
			if (nonceExtension == null || !Arrays.equals(nonce, ASN1OctetString.getInstance(nonceExtension.getParsedValue()).getOctets())) {
				throw new GeneralSecurityException("OCSP nonce mismatch");
			}
			X509Certificate responder = issuer;
			X509CertificateHolder[] embedded = basic.getCerts();
			if (embedded.length > 1) {
				throw new GeneralSecurityException("Ambiguous OCSP responder");
			}
			if (embedded.length == 1) {
				responder = new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter().setProvider(provider).getCertificate(embedded[0]);
				WebEidCertificates.validate(responder, issuer, clock, false, null);
			}
			if (!basic.getResponderId().equals(new org.bouncycastle.cert.ocsp.RespID(new JcaX509CertificateHolder(responder).getSubjectPublicKeyInfo(), new org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder().setProvider(provider).build().get(CertificateID.HASH_SHA1)))
					&& !basic.getResponderId().equals(new org.bouncycastle.cert.ocsp.RespID(new org.bouncycastle.asn1.x500.X500Name(responder.getSubjectX500Principal().getName())))) {
				throw new GeneralSecurityException("OCSP responder identity mismatch");
			}
			if (!basic.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider(provider).build(responder.getPublicKey()))) {
				throw new GeneralSecurityException("Invalid OCSP signature");
			}
			SingleResp[] entries = basic.getResponses();
			if (entries.length != 1 || !id.equals(entries[0].getCertID())) {
				throw new GeneralSecurityException("OCSP certificate identity mismatch");
			}
			Date now = Date.from(clock.instant());
			Date thisUpdate = entries[0].getThisUpdate();
			Date nextUpdate = entries[0].getNextUpdate();
			if (thisUpdate == null || nextUpdate == null || thisUpdate.after(new Date(now.getTime() + 300000))
					|| thisUpdate.before(new Date(now.getTime() - 600000)) || nextUpdate.before(now)
					|| nextUpdate.before(thisUpdate) || basic.getProducedAt() == null || basic.getProducedAt().after(new Date(now.getTime() + 300000))
					|| basic.getProducedAt().before(thisUpdate)) {
				throw new GeneralSecurityException("Stale OCSP response");
			}
			CertificateStatus status = entries[0].getCertStatus();
			if (status instanceof RevokedStatus) {
				throw new GeneralSecurityException("Certificate revoked");
			}
			if (status instanceof UnknownStatus || status != CertificateStatus.GOOD) {
				throw new GeneralSecurityException("Unknown certificate status");
			}
			return responseBytes.clone();
		}
		catch (org.bouncycastle.cert.ocsp.OCSPException | org.bouncycastle.operator.OperatorCreationException
				| org.bouncycastle.cert.CertIOException e) {
			throw new GeneralSecurityException("OCSP validation failed", e);
		}
	}
}
