package be.nabu.utils.security;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Reader;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.CRLSelector;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertSelector;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaCRLStore;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaCertStoreBuilder;
import org.bouncycastle.cert.jcajce.JcaX500NameUtil;
import org.bouncycastle.cert.jcajce.JcaX509CRLHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSCompressedDataParser;
import org.bouncycastle.cms.CMSCompressedDataStreamGenerator;
import org.bouncycastle.cms.CMSEnvelopedDataParser;
import org.bouncycastle.cms.CMSEnvelopedDataStreamGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataStreamGenerator;
import org.bouncycastle.cms.CMSTypedStream;
import org.bouncycastle.cms.KeyAgreeRecipientId;
import org.bouncycastle.cms.KeyTransRecipientId;
import org.bouncycastle.cms.RecipientId;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JcaX509CertSelectorConverter;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.ZlibCompressor;
import org.bouncycastle.cms.jcajce.ZlibExpanderProvider;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.MiscPEMGenerator;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMEncryptor;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.Selector;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.io.pem.PemWriter;

import be.nabu.utils.codec.TranscoderUtils;
import be.nabu.utils.codec.impl.Base64Decoder;
import be.nabu.utils.codec.impl.Base64Encoder;
import be.nabu.utils.io.IOUtils;
import be.nabu.utils.io.api.ByteBuffer;
import be.nabu.utils.io.api.ReadableContainer;
import be.nabu.utils.io.api.WritableContainer;
import be.nabu.utils.security.SecurityUtils.DigestGenerator;
import be.nabu.utils.security.api.ManagedKeyStore;

/**
 * Interesting classes to look at can be found in org.bouncycastle.mail.smime
 * For example a lot of information was gleaned from SMIMESignedGenerator
 */
public class BCSecurityUtils {
	
	/**
	 * Register if necessary
	 */
	static {
		loadLibrary();
	}
	
	public static void loadLibrary() {
		if (Security.getProvider("BC") == null)
			Security.addProvider(new BouncyCastleProvider());
	}
	/**
	 * Creates a CSR (certificate signing request) for a specific keypair
	 * However it hinges on sun-specific classes
	 * @throws SignatureException 
	 * @throws NoSuchProviderException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 */
//	public static byte [] generatePKCS10(KeyPair pair, SignatureType type, String commonName, String organisation, String organisationalUnit, String locality, String state, String country) throws NoSuchAlgorithmException, InvalidKeyException, IOException, CertificateException, SignatureException {
//		PKCS10 pkcs10 = new PKCS10(pair.getPublic());
//		Signature signature = Signature.getInstance(type.toString());
//		signature.initSign(pair.getPrivate());
//		X500Name x500Name = new X500Name(commonName, organisationalUnit, organisation, locality, state, country);
//		pkcs10.encodeAndSign(new X500Signer(signature, x500Name));
//		ByteArrayOutputStream output = new ByteArrayOutputStream();
//        PrintStream printer = new PrintStream(output);
//        pkcs10.print(printer);
//        return output.toByteArray();
//	}
	
//	@Deprecated
//	public static ReadableByteContainer generatePKCS10DER(KeyPair pair, SignatureType type, X500Principal subject) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
//		org.bouncycastle.jce.PKCS10CertificationRequest request = new org.bouncycastle.jce.PKCS10CertificationRequest(type.toString(), subject, pair.getPublic(), null, pair.getPrivate());
//		return IOUtils.wrap(request.getEncoded(), true);
//	}
	
	public static byte[] generatePKCS10(KeyPair pair, SignatureType type, X500Principal subject, String...alternateDomains) throws IOException {
		PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(
			subject,
			pair.getPublic()
		);
		if (alternateDomains != null && alternateDomains.length > 0) {
			GeneralName[] names = new GeneralName[alternateDomains.length];
			for (int i = 0; i < alternateDomains.length; i++) {
				names[i] = new GeneralName(GeneralName.dNSName, alternateDomains[i]);
			}
			GeneralNames subjectAltName = new GeneralNames(names);
			ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
			extensionsGenerator.addExtension(Extension.subjectAlternativeName, false, subjectAltName);
			builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensionsGenerator.generate());
		}
//		builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensions.generate()); 
		AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(type.toString());
		AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
		AsymmetricKeyParameter keyParam = PrivateKeyFactory.createKey(pair.getPrivate().getEncoded());
		try {
			ContentSigner signer = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(keyParam);
			PKCS10CertificationRequest csr = builder.build(signer);
			ContentVerifierProvider verifier = new JcaContentVerifierProviderBuilder().setProvider("BC").build(pair.getPublic());
			csr.isSignatureValid(verifier);
			return csr.getEncoded();
		}
		catch (OperatorCreationException e) {
			throw new IOException(e);
		}
		catch (PKCSException e) {
			throw new IOException(e);
		}
	}
	
	public static X500Principal getPKCS10Subject(Reader csr) throws IOException {
		return new X500Principal(parsePKCS10(csr).getSubject().toString());
	}
	
	/**
	 * The parser only works with the base64 encoded version of the csr
	 * Passing in the csr as decoded binary will result in readObject() returning null (no exception)
	 */
	public static PKCS10CertificationRequest parsePKCS10(Reader csr) throws IOException {
		PEMParser parser = new PEMParser(csr);
		try {
			return (PKCS10CertificationRequest) parser.readObject();
		}
		finally {
			parser.close();
		}
	}

	public static KeyPair parseSSHKey(Reader csr, String password) throws IOException {
		PEMEncryptedKeyPair keypair = (PEMEncryptedKeyPair) parsePem(csr);
		PEMDecryptorProvider decryptor = new JcePEMDecryptorProviderBuilder().build(password == null ? new char[0] : password.toCharArray());
		PEMKeyPair decryptedKeyPair = keypair.decryptKeyPair(decryptor);
		return new JcaPEMKeyConverter().getKeyPair(decryptedKeyPair);
	}

	private static byte[] encodePublicKey(RSAPublicKey key) throws IOException {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		// encode the "ssh-rsa" string
		byte[] sshrsa = new byte[] { 0, 0, 0, 7, 's', 's', 'h', '-', 'r', 's', 'a' };
		out.write(sshrsa);
		// encode the public exponent
		BigInteger e = key.getPublicExponent();
		byte[] data = e.toByteArray();
		encodeUInt32(data.length, out);
		out.write(data);
		// encode the modulus
		BigInteger m = key.getModulus();
		data = m.toByteArray();
		encodeUInt32(data.length, out);
		out.write(data);
		return out.toByteArray();
	}

	private static void encodeUInt32(int value, OutputStream out) throws IOException {
		byte[] tmp = new byte[4];
		tmp[0] = (byte) ((value >>> 24) & 0xff);
		tmp[1] = (byte) ((value >>> 16) & 0xff);
		tmp[2] = (byte) ((value >>> 8) & 0xff);
		tmp[3] = (byte) (value & 0xff);
		out.write(tmp);
	}

	public static void writeSSHKey(Writer writer, PublicKey key) throws IOException {
		ByteArrayOutputStream output = new ByteArrayOutputStream();
		Base64Encoder transcoder = new Base64Encoder();
		transcoder.setBytesPerLine(0);
		WritableContainer<ByteBuffer> encoded = TranscoderUtils.wrapWritable(IOUtils.wrap(output), transcoder);
		encoded.write(IOUtils.wrap(encodePublicKey((RSAPublicKey) key), true));
		encoded.close();
		// the fields in a protocol 2 public key are:
		// <keytype> <key> [<comment>]
		// a lot of systems will generate the username and hostname as comment, e.g. "alex@chaos" but it is optional
		// the trailing linefeed is (presumably) not absolutely required but can be expected, especially when adding it to the authorized_keys file using the ">>" syntax
		writer.write("ssh-rsa " + new String(output.toByteArray()) + "\n");
	}
	
	public static void writeSSHKey(Writer writer, PrivateKey key, String password) throws IOException {
		PemWriter pemWriter = new PemWriter(writer);
		MiscPEMGenerator generator;
		if (password != null) {
			// the default algorithm for ssh keys (at least on this system)
			PEMEncryptor build = new JcePEMEncryptorBuilder("AES-128-CBC").build(password == null ? new char[0] : password.toCharArray());
			generator = new JcaMiscPEMGenerator(key, build);
		}
		else {
			generator = new JcaMiscPEMGenerator(key);
		}
		pemWriter.writeObject(generator);
		pemWriter.flush();
	}
	
	public static void writePem(Writer writer, PublicKey key) throws IOException {
		PemWriter pemWriter = new PemWriter(writer);
		MiscPEMGenerator generator = new JcaMiscPEMGenerator(key);
		pemWriter.writeObject(generator);
		pemWriter.flush();
	}
	
	public static Object parsePem(Reader csr) throws IOException {
		PEMParser parser = new PEMParser(csr);
		try {
			return parser.readObject();
		}
		finally {
			parser.close();
		}
	}
	
	public static void encodePKCS10(InputStream csr, Writer output) throws UnsupportedEncodingException, IOException {
		output.write("-----BEGIN CERTIFICATE REQUEST-----\n".toCharArray());
		ReadableContainer<ByteBuffer> encoded = TranscoderUtils.transcodeBytes(IOUtils.wrap(csr), new Base64Encoder());
		// this makes a string out of it and adds linefeeds
		output.write(IOUtils.toString(IOUtils.wrapReadable(encoded, Charset.forName("ASCII")))
			.replaceAll("([\\w/+=]{77})", "$1\n")
			.toCharArray());
		output.write("\n-----END CERTIFICATE REQUEST-----".toCharArray());
	}
	
	public static X509Certificate generateSelfSignedCertificate(KeyPair pair, Date until, X500Principal issuer, X500Principal subject) throws CertificateException, IOException {
		return generateSelfSignedCertificate(pair, until, issuer, subject, SignatureType.SHA1WITHRSA);
	}
	
	public static X509Certificate generateSelfSignedCertificate(KeyPair pair, Date until, X500Principal issuer, X500Principal subject, SignatureType signatureType) throws CertificateException, IOException {
		// the critical difference between v1 and v3 certificates is that v3 can have extensions whereas v1 can't (not entirely sure what v2's trick is...)
		// interestingly enough you _need_ extensions when signing an intermediate
		// http://unitstep.net/blog/2009/03/16/using-the-basic-constraints-extension-in-x509-v3-certificates-for-intermediate-cas/
		// or you can get errors like: java.security.cert.CertPathValidatorException: Intermediate certificate lacks BasicConstraints
		// for root CA's it depends on the system, most root CA's are identified by the fact that they signed themselves, but sometimes the constraints are required as well
//		X509v1CertificateBuilder builder = new JcaX509v1CertificateBuilder(
//			issuer,
//			SecurityUtils.generateSerialId(),
//			new Date(),
//			until,
//			subject,
//			pair.getPublic()
//		);
		X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
			issuer,
			SecurityUtils.generateSerialId(),
			new Date(),
			until,
			subject,
			pair.getPublic()
		);
		try {
			builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true))
            	.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign));
			X509CertificateHolder holder = builder.build(getContentSigner(pair.getPrivate(), signatureType));
			return getCertificate(holder);
		}
		catch (OperatorCreationException e) {
			throw new RuntimeException(e);
		}
	}
	
	public static X509Certificate signPKCS10(byte [] csr, Date until, X500Principal issuer, PrivateKey privateKey) throws IOException, CertificateException, InvalidKeyException, NoSuchAlgorithmException {
		return signPKCS10(csr, until, issuer, privateKey, SignatureType.SHA1WITHRSA);
	}
	public static X509Certificate signPKCS10(byte [] csr, Date until, X500Principal issuer, PrivateKey privateKey, SignatureType type) throws IOException, CertificateException, InvalidKeyException, NoSuchAlgorithmException {
		// the conversion from X500Principal to X500Name is NOT correct in the below commented part
//		PKCS10CertificationRequest pkcs10 = new PKCS10CertificationRequest(IOUtils.toBytes(csr));
//		X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
//				new X500Name(issuer.getName()),
//				SecurityUtils.generateSerialId(),
//				new Date(),
//				until,
//				pkcs10.getSubject(),
//				pkcs10.getSubjectPublicKeyInfo()
//		);
		// so let's do it the JCA way
		JcaPKCS10CertificationRequest pkcs10 = new JcaPKCS10CertificationRequest(csr);
		X509v1CertificateBuilder builder = new JcaX509v1CertificateBuilder(
				issuer,
				SecurityUtils.generateSerialId(),
				new Date(),
				until,
				new X500Principal(pkcs10.getSubject().getEncoded()),
				pkcs10.getPublicKey()
		);

		try {
			X509CertificateHolder holder = builder.build(getContentSigner(privateKey, type));
			return getCertificate(holder);
		}
		catch (OperatorCreationException e) {
			throw new IOException(e);
		}
	}
	
	// example: https://github.com/joschi/cryptoworkshop-bouncycastle/blob/master/src/main/java/cwguide/JcaUtils.java
	// the path length indicates how many more intermediates may follow this one, if 0, it can only sign end entity certificates
	// if not set, the path can go on indefinately
	// http://stackoverflow.com/questions/6616470/certificates-basic-constraints-path-length
	public static X509Certificate signPKCS10AsIntermediate(byte [] csr, Date until, X500Principal issuer, PrivateKey privateKey, SignatureType type, X509Certificate caCertificate, Integer pathLength) throws IOException, CertificateException, InvalidKeyException, NoSuchAlgorithmException {
		JcaPKCS10CertificationRequest pkcs10 = new JcaPKCS10CertificationRequest(csr);
		X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
			issuer,
			SecurityUtils.generateSerialId(),
			new Date(),
			until,
			new X500Principal(pkcs10.getSubject().getEncoded()),
			pkcs10.getPublicKey()
		);

		try {
			JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
			builder.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(caCertificate))
	            .addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(pkcs10.getPublicKey()))
	            .addExtension(Extension.basicConstraints, true, pathLength == null ? new BasicConstraints(true) : new BasicConstraints(pathLength))
            	.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign));
			X509CertificateHolder holder = builder.build(getContentSigner(privateKey, type));
			return getCertificate(holder);
		}
		catch (OperatorCreationException e) {
			throw new IOException(e);
		}
	}
	
	// TODO: not sure what the proper key usage would be for a "regular" entity
	public static X509Certificate signPKCS10AsEntity(byte [] csr, Date until, X500Principal issuer, PrivateKey privateKey, SignatureType type, X509Certificate caCertificate) throws IOException, CertificateException, InvalidKeyException, NoSuchAlgorithmException {
		JcaPKCS10CertificationRequest pkcs10 = new JcaPKCS10CertificationRequest(csr);
		X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
			issuer,
			SecurityUtils.generateSerialId(),
			new Date(),
			until,
			new X500Principal(pkcs10.getSubject().getEncoded()),
			pkcs10.getPublicKey()
		);

		try {
			JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
			builder.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(caCertificate))
	            .addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(pkcs10.getPublicKey()))
	            .addExtension(Extension.basicConstraints, true, new BasicConstraints(false))
            	.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
			X509CertificateHolder holder = builder.build(getContentSigner(privateKey, type));
			return getCertificate(holder);
		}
		catch (OperatorCreationException e) {
			throw new IOException(e);
		}
	}
	
	private static ContentSigner getContentSigner(PrivateKey privateKey, SignatureType type) throws IOException, OperatorCreationException {
		AsymmetricKeyParameter keyParameter = PrivateKeyFactory.createKey(privateKey.getEncoded());
		AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(type.toString());
		AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
		return new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(keyParameter);
	}
	
	private static X509Certificate getCertificate(X509CertificateHolder holder) throws CertificateException {
		return new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
	}
	
	@SuppressWarnings("unused")
	private static PublicKey getPublicKey(SubjectPublicKeyInfo info) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
		RSAKeyParameters rsa = (RSAKeyParameters) PublicKeyFactory.createKey(info);
		RSAPublicKeySpec rsaSpec = new RSAPublicKeySpec(rsa.getModulus(), rsa.getExponent());
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		return keyFactory.generatePublic(rsaSpec);
//		SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(publicKey);
	}
	
	public static KeyStoreHandler generateNewCSR(KeyPair pair, X500Principal subject, SignatureType signatureType, OutputStream csr, String password) throws NoSuchAlgorithmException, CertificateException, KeyStoreException, NoSuchProviderException, IOException {
		KeyStoreHandler selfHandler = KeyStoreHandler.create(password, StoreType.PKCS12);
//		BCSecurityUtils.signPKCS10(IOUtils.wrap(content, true), until, issuer, privateKey)
		csr.write(BCSecurityUtils.generatePKCS10(pair, signatureType, subject));
		return selfHandler;
	}
//	
//	/**
//	 * The CMS stands for cryptographic message syntax
//	 * It builds on PKCS7 to allow encryption/signing of data
//	 * @param signatures
//	 * @return
//	 */
//	public static CMSSignedData generateCMSSignedData(boolean encapsulate, Signature...signatures) {
//		CMSTypedData message = new CMSProcessableByteArray(signature.sign());
//		CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
//		gen.adds
//	}
	
	@SuppressWarnings({ "unchecked", "rawtypes" })
	public static List<X509Certificate> parsePKCS7Certificates(byte [] content) throws CertificateException, IOException, OperatorCreationException {
		try {
			if (content[0] == '-') {
				String stringContent = new String(content);
				stringContent = stringContent.replaceAll("(?s)[\\s]*-[-]+.*?(BEGIN|END)[\\s\\w]*[-]+-[\\s]*", "");
				ReadableContainer<ByteBuffer> decoded = TranscoderUtils.transcodeBytes(IOUtils.wrap(stringContent.getBytes(), true), new Base64Decoder());
				content = IOUtils.toBytes(decoded);
			}
			CMSSignedData data = new CMSSignedData(content);
			Store certStore = data.getCertificates();
			List<X509Certificate> result = new ArrayList<X509Certificate>();

			SignerInformationStore signerInfos = data.getSignerInfos();
			Collection<SignerInformation> signers = signerInfos.getSigners();
			// pkcs7 is commonly used without actual content and no signer infos but only certificates and/or crls
			if (signers.isEmpty()) {
				Collection<X509CertificateHolder> matches = certStore.getMatches(null);
				for (X509CertificateHolder holder : matches) {
					result.add(new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder));
				}
			}
			else {
				for (SignerInformation signer : signers) {
					Collection<X509CertificateHolder> matches = certStore.getMatches(signer.getSID());
					for (X509CertificateHolder holder : matches) {
						result.add(new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder));
					}
				}
			}
			return result;
		}
		catch (CMSException e) {
			throw new RuntimeException(e);
		}
	}
	
	/**
	 * The method currently does not support attribute certificates, but it is supported by the generator so could be added easily
	 * @param certStores
	 * @throws GeneralSecurityException
	 */
	private static CMSSignedDataStreamGenerator createSignatureGenerator(SignerInfoGenerator [] signers, CertStore...certStores) throws GeneralSecurityException {
		CMSSignedDataStreamGenerator generator = new CMSSignedDataStreamGenerator();
		try {
			for (CertStore certStore : certStores) {
				generator.addCertificates(convertToCertificateStore(certStore));
				generator.addCRLs(convertToCRLStore(certStore));
			}
//			generator.addSigners(signers);
			for (SignerInfoGenerator signer : signers)
				generator.addSignerInfoGenerator(signer);
			return generator;
		}
		catch (CMSException e) {
			throw new GeneralSecurityException(e);
		}
	}
	
	public static boolean [] KEY_USAGE_DIGITAL_SIGNATURE = new boolean [] {
		true, false, false, false, false, false, false, false, false
	};

	/**
	 * Use this if the signatures are not encapsulated. Provide the necessary signatures in the second parameter
	 */
	public static CertPath verify(InputStream unencapsulatedSignedData, byte [] signatures, CertStore certsAndCRLs, X509Certificate...trustedRootCertificates) throws GeneralSecurityException, IOException {
		try {
//			CMSSignedData cmsSignedData = new CMSSignedData(IOUtils.toInputStream(signedData));
			DigestGenerator digestGenerator = new DigestGenerator(DigestAlgorithm.SHA1, DigestAlgorithm.SHA256, DigestAlgorithm.SHA512, DigestAlgorithm.MD5);
			IOUtils.copyBytes(IOUtils.wrap(unencapsulatedSignedData), digestGenerator);
			digestGenerator.close();
//			CMSSignedData cmsSignedData = new CMSSignedData(getDigests(data, certsAndCRLs), IOUtils.toBytes(signatures));
			CMSSignedData cmsSignedData = new CMSSignedData(digestGenerator.getDigestsByOID(), signatures);
			return verify(cmsSignedData, certsAndCRLs, trustedRootCertificates);
		}
		catch (CMSException e) {
			throw new GeneralSecurityException(e);
		}
	}

	/**
	 * Use this if the signatures are encapsulated into the signed data
	 */
	public static CertPath verify(InputStream encapsulatedSignedData, CertStore certsAndCRLs, X509Certificate...trustedRootCertificates) throws GeneralSecurityException, IOException {
		try {
			return verify(new CMSSignedData(encapsulatedSignedData), certsAndCRLs, trustedRootCertificates);
		}
		catch (CMSException e) {
			throw new GeneralSecurityException(e);
		}
	}
	
	private static CertPath verify(CMSSignedData cmsSignedData, CertStore certsAndCRLs, X509Certificate...trustedRootCertificates) throws GeneralSecurityException, IOException {
		try {
			SignerInformationStore signers = cmsSignedData.getSignerInfos();
			for (SignerInformation signer : (Collection<SignerInformation>) signers.getSigners()) {
				X509CertSelector selector = new JcaX509CertSelectorConverter().getCertSelector(signer.getSID());
				selector.setKeyUsage(KEY_USAGE_DIGITAL_SIGNATURE);
				PKIXCertPathBuilderResult result = createPKIXPath(selector, certsAndCRLs, trustedRootCertificates);
				if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build((X509Certificate) result.getCertPath().getCertificates().get(0))))
					return result.getCertPath();
			}
			return null;
		}
		catch (CMSException e) {
			throw new GeneralSecurityException(e);
		}
		catch (OperatorCreationException e) {
			throw new GeneralSecurityException(e);
		}
	}
	
	@SuppressWarnings({ "unchecked", "rawtypes" })
	public static CertPath verify2(byte [] signatures, CertStore certsAndCRLs, X509Certificate...trustedRootCertificates) throws GeneralSecurityException {
		try {
//			CMSSignedData cmsSignedData = new CMSSignedData(IOUtils.toInputStream(signedData));
			CMSSignedData cmsSignedData = new CMSSignedData(signatures);
			Store store = cmsSignedData.getCertificates();
			SignerInformationStore signers = cmsSignedData.getSignerInfos();
			for (SignerInformation signer : (Collection<SignerInformation>) signers.getSigners()) {
				System.out.println("signer: " + signer.getSID().getIssuer());
				System.out.println(store.getMatches(new AllSelector()));
				Collection<X509CertSelector> selectors = store.getMatches(signer.getSID());
				if (selectors.size() > 0) {
					X509CertSelector selector = (X509CertSelector) store.getMatches(signer.getSID()).iterator().next();
					selector.setKeyUsage(KEY_USAGE_DIGITAL_SIGNATURE);
					PKIXCertPathBuilderResult result = createPKIXPath(selector, certsAndCRLs, trustedRootCertificates);
					System.out.println("checking " + ((X509Certificate) result.getCertPath().getCertificates().get(0)).getSubjectX500Principal() + " vs " + signer.getSID().getIssuer());
					if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build((X509Certificate) result.getCertPath().getCertificates().get(0))))
						result.getCertPath();
				}
			}
			return null;
		}
		catch (CMSException e) {
			throw new GeneralSecurityException(e);
		}
		catch (OperatorCreationException e) {
			throw new GeneralSecurityException(e);
		}
	}
	
	
	public static PKIXCertPathBuilderResult createPKIXPath(X509CertSelector endConstraints, CertStore certsAndCRLs, X509Certificate...rootCertificates) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, CertPathBuilderException, CertStoreException {
		TrustAnchor [] trustAnchors = new TrustAnchor[rootCertificates.length];
		for (int i = 0; i < rootCertificates.length; i++)
			trustAnchors[i] = new TrustAnchor(rootCertificates[i], null);
		
		CertPathBuilder builder = CertPathBuilder.getInstance("PKIX", "BC");
		PKIXBuilderParameters buildParams = new PKIXBuilderParameters(new HashSet<TrustAnchor>(Arrays.asList(trustAnchors)), endConstraints);
		
		buildParams.addCertStore(certsAndCRLs);
		// only enable crls if there are any
		buildParams.setRevocationEnabled(certsAndCRLs.getCRLs(new AllCRLSelector()).size() > 0);

		return (PKIXCertPathBuilderResult) builder.build(buildParams);
	}
	
	static SignerId [] createIdentifiers(X509Certificate...certificates) {
		SignerId [] identifiers = new SignerId[certificates.length];
		for (int i = 0; i < certificates.length; i++) {
			X500Name name = new X500Name(certificates[i].getSubjectX500Principal().getName());
			identifiers[i] = new SignerId(name, certificates[0].getSerialNumber());
		}
		return identifiers;
	}

	public static SignedOutputStream sign(OutputStream output, SignerInfoGenerator [] signers, boolean encapsulate, CertStore...certStores) throws GeneralSecurityException, IOException {
		CMSSignedDataStreamGenerator streamGenerator = createSignatureGenerator(signers, certStores);
		// for s/mime (currently our only target), the data should never be encapsulated (forgot where I read this, may be untrue!)
		OutputStream signedOutput = streamGenerator.open(output, encapsulate);
		return new SignedOutputStream(signedOutput, streamGenerator);
	}
	
	/**
	 * This does not work though i have no idea why
	 * The resulting map is always empty
	 */
	static Map<String, byte[]> getDigests(InputStream data, CertStore...certStores) throws GeneralSecurityException, IOException {
		try {
			CMSSignedDataStreamGenerator generator = new CMSSignedDataStreamGenerator();
			for (CertStore certStore : certStores) {
				generator.addCertificates(convertToCertificateStore(certStore));
				generator.addCRLs(convertToCRLStore(certStore));
			}
			OutputStream signedOutput = generator.open(IOUtils.toOutputStream(IOUtils.newByteSink()), false);
			SignedOutputStream output = new SignedOutputStream(signedOutput, generator); 
			IOUtils.copyBytes(IOUtils.wrap(data), IOUtils.wrap(output));
			output.close();
			return output.getDigests();
		}
		catch (CMSException e) {
			throw new GeneralSecurityException(e);
		}
	}
	
	private static JcaCertStore convertToCertificateStore(CertStore store) throws CertificateEncodingException, CertStoreException {
		return new JcaCertStore(store.getCertificates(new AllCertSelector()));
	}
	
	private static JcaCRLStore convertToCRLStore(CertStore store) throws CRLException, CertStoreException {
		return new JcaCRLStore(store.getCRLs(new AllCRLSelector()));
	}
	
	public static SignerInfoGenerator createSigner(PrivateKey privateKey, X509Certificate certificate, SignatureType signatureType) throws GeneralSecurityException {
		// could also use org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder
		try {
			ContentSigner signer = new JcaContentSignerBuilder(signatureType.toString()).setProvider("BC").build(privateKey);
			return new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
				.build(signer, certificate);
		}
		catch (OperatorCreationException e) {
			throw new GeneralSecurityException(e);
		}
	}

	public static SignerInfoGenerator [] createSignerStore(SignerInfoGenerator...signers) {
		return signers;
	}
	
	public static PKIXCertPathBuilderResult validateCertificateChain(X509Certificate [] chain, X509Certificate...certificates) throws GeneralSecurityException {
		CertStore certStore = createCertificateStore(SecurityUtils.getIntermediateCertificates(certificates));
		
		// create a selector that specifies the starting certificate
		X509CertSelector selector = new X509CertSelector(); 
		selector.setCertificate(chain[0]);
		
		return createPKIXPath(selector, certStore, SecurityUtils.getRootCertificates(certificates));
	}
		
	/**
	 * The aliases must point to private keys
	 * @throws GeneralSecurityException 
	 * @throws KeyStoreException 
	 * @throws IOException 
	 */
	public static SignerInfoGenerator [] createSignerStore(SignatureType signatureType, ManagedKeyStore keyStore, String...aliases) throws KeyStoreException, GeneralSecurityException, IOException {
		List<SignerInfoGenerator> signers = new ArrayList<SignerInfoGenerator>();
		for (String alias : aliases)
			signers.add(createSigner(keyStore.getPrivateKey(alias), keyStore.getChain(alias)[0], signatureType));
		return signers.toArray(new SignerInfoGenerator[signers.size()]);
	}

//	public static SignerInformationStore createSignerStore(SignerInfoGenerator...signers) {
//		// not correct, it takes SignerInformation objects, not sure how to get from the generator to one of those  
//		return new SignerInformationStore(Arrays.asList(signers));
//	}
	
	public static CertStore createCertificateStore(X509Certificate [] certificates, X509CRL...certificateRevocationLists) throws GeneralSecurityException {
		JcaCertStoreBuilder builder = new JcaCertStoreBuilder();
		for (X509Certificate certificate : certificates)
			builder.addCertificate(new JcaX509CertificateHolder(certificate));
		for (X509CRL certificateRevocationList : certificateRevocationLists)
			builder.addCRL(new JcaX509CRLHolder(certificateRevocationList));
		return builder.build();
	}
	
	public static class AllCertSelector implements CertSelector {
		@Override
		public boolean match(Certificate certificate) {
			return true;
		}
		@Override
		public AllCertSelector clone() {
			return new AllCertSelector();
		}
	}
	
	public static class AllCRLSelector implements CRLSelector {

		@Override
		public boolean match(CRL crl) {
			return true;
		}
		@Override
		public AllCRLSelector clone() {
			return new AllCRLSelector();
		}
	}
	
	public static class AllSelector implements Selector {
		@Override
		public boolean match(Object argument) {
			return true;
		}
		@Override
		public AllSelector clone() {
			return new AllSelector();
		}
	}
	
	public static class SignedOutputStream extends OutputStream {

		private OutputStream parent;
		private CMSSignedDataStreamGenerator generator;
		private boolean closed = false;
		private byte [] single = new byte[1];
		
		SignedOutputStream(OutputStream signedParent, CMSSignedDataStreamGenerator generator) {
			this.parent = signedParent;
			this.generator = generator;
		}
		
		@Override
		public void close() throws IOException {
			if (!closed) {
				closed = true;
				parent.close();
			}
		}

		@Override
		public void flush() throws IOException {
			parent.flush();
		}

		@Override
		public void write(byte[] bytes) throws IOException {
			parent.write(bytes);
		}

		@Override
		public void write(byte[] bytes, int offset, int length) throws IOException {
			parent.write(bytes, offset, length);
		}
		
		/**
		 * Only call this after you have closed the output
		 * Returns oids  > digests
		 */
		@SuppressWarnings("unchecked")
		public Map<String, byte[]> getDigests() {
			return closed ? generator.getGeneratedDigests() : null;
		}

		@Override
		public void write(int i) throws IOException {
			single[0] = (byte) i;
			write(single);
		}
	}
	
	public static OutputStream compress(OutputStream output) throws IOException {
		CMSCompressedDataStreamGenerator generator = new CMSCompressedDataStreamGenerator();
		// in theory the compressor can be any OutputCompressor, but in practic eonly zlib is currently implemented
		OutputStream compressedOutput = generator.open(output, new ZlibCompressor());
		return compressedOutput;
	}
	
	public static InputStream decompress(InputStream container) throws GeneralSecurityException {
		try {
			CMSCompressedDataParser parser = new CMSCompressedDataParser(container);
			InputStream input = parser.getContent(new ZlibExpanderProvider()).getContentStream();
			return input;
		}
		catch (CMSException e) {
			throw new GeneralSecurityException(e);
		}
	}
	
	public static OutputStream encrypt(OutputStream output, SynchronousEncryptionAlgorithm algorithm, X509Certificate...recipients) throws GeneralSecurityException, IOException {
		CMSEnvelopedDataStreamGenerator generator = new CMSEnvelopedDataStreamGenerator();
		for (X509Certificate recipient : recipients)
			generator.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(recipient).setProvider("BC"));
		try {
			OutputStream encryptedOut = generator.open(output, 
				new JceCMSContentEncryptorBuilder(algorithm.getIdentifier()).setProvider("BC").build());
			return encryptedOut;
		}
		catch (CMSException e) {
			throw new GeneralSecurityException(e);
		}
	}
	
	public static InputStream decrypt(InputStream input, PrivateKey privateKey) throws GeneralSecurityException, IOException {
		return decrypt(input, privateKey, null);
	}
	
	/**
	 * In some cases the encryption can be targeted at multiple recipients
	 * You can only decrypt one of them with your private key so you need to pass along the serialId of your certificate to figure out the correct recipient
	 * Note that not all recipient types support serialId selection!
	 */
	public static InputStream decrypt(InputStream input, PrivateKey privateKey, BigInteger serialId) throws GeneralSecurityException, IOException {
		try {
			CMSEnvelopedDataParser parser = new CMSEnvelopedDataParser(input);
			RecipientInformationStore recipients = parser.getRecipientInfos();
			for (RecipientInformation recipient : (Collection<RecipientInformation>) recipients.getRecipients()) {
				// check if it is you
				if (serialId != null) {
					RecipientId recipientId = recipient.getRID();
					if (recipientId instanceof KeyTransRecipientId) {
						if (!((KeyTransRecipientId) recipientId).getSerialNumber().equals(serialId))
							continue;
					}
					else if (recipientId instanceof KeyAgreeRecipientId) {
						if (!((KeyAgreeRecipientId) recipientId).getSerialNumber().equals(serialId))
							continue;
					}
					else
						throw new GeneralSecurityException("You defined a specific recipient but the encrypted content does not support serialId selection of recipients");
				}
				return decrypt(recipient, privateKey);
			}
			throw new GeneralSecurityException("Could not find encrypted content for the recipient with serial number: " + serialId);
		}
		catch (CMSException e) {
			throw new GeneralSecurityException(e);
		}
	}
	
	public static InputStream decrypt(InputStream input, ManagedKeyStore managedKeyStore) throws GeneralSecurityException, IOException {
		try {
			KeyStoreHandler handler = new KeyStoreHandler(managedKeyStore.getKeyStore());
			List<String> aliases = handler.getPrivateKeyAliases();
			CMSEnvelopedDataParser parser = new CMSEnvelopedDataParser(input);
			RecipientInformationStore recipients = parser.getRecipientInfos();
			for (RecipientInformation recipient : (Collection<RecipientInformation>) recipients.getRecipients()) {
				RecipientId recipientId = recipient.getRID();
				PrivateKey privateKey = null;
				// check if you have a matching private key
				for (String alias : aliases) {
					X509Certificate[] chain = managedKeyStore.getChain(alias);
					X509Certificate issuer = chain.length == 1 ? chain[0] : chain[1];
					if (recipientId instanceof KeyTransRecipientId) {
						if (((KeyTransRecipientId) recipientId).getIssuer().equals(JcaX500NameUtil.getIssuer(issuer)) && ((KeyTransRecipientId) recipientId).getSerialNumber().equals(chain[0].getSerialNumber())) {
							privateKey = managedKeyStore.getPrivateKey(alias);
							break;
						}
					}
					else if (recipientId instanceof KeyAgreeRecipientId) {
						if (((KeyAgreeRecipientId) recipientId).getSerialNumber().equals(chain[0].getSerialNumber())) {
							privateKey = managedKeyStore.getPrivateKey(alias);
							break;
						}
					}
					else
						throw new GeneralSecurityException("You defined a specific keystore but the encrypted content does not support selection of recipients");
				}
				return decrypt(recipient, privateKey);
			}
			throw new GeneralSecurityException("Could not find encrypted content for any of the recipients in the keystore");
		}
		catch (CMSException e) {
			throw new GeneralSecurityException(e);
		}
	}
	
	private static InputStream decrypt(RecipientInformation recipient, PrivateKey privateKey) throws GeneralSecurityException, IOException, CMSException {
		CMSTypedStream typedStream = recipient.getContentStream(new JceKeyTransEnvelopedRecipient(privateKey).setProvider("BC"));
		return typedStream.getContentStream();
	}

}
