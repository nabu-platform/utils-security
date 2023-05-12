package be.nabu.utils.security;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Writer;
import java.math.BigInteger;
import java.net.IDN;
import java.net.UnknownHostException;
import java.nio.charset.Charset;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;
import javax.xml.crypto.Data;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.URIReference;
import javax.xml.crypto.URIReferenceException;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;

import org.mindrot.jbcrypt.BCrypt;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import be.nabu.utils.codec.TranscoderUtils;
import be.nabu.utils.codec.impl.Base64Decoder;
import be.nabu.utils.codec.impl.Base64Encoder;
import be.nabu.utils.io.IOUtils;
import be.nabu.utils.io.api.ByteBuffer;
import be.nabu.utils.io.api.Container;
import be.nabu.utils.io.api.ReadableContainer;
import be.nabu.utils.io.api.WritableContainer;
import be.nabu.utils.io.containers.chars.HexReadableCharContainer;

public class SecurityUtils {
	
	public static X509TrustManager createTrustAllManager() {
		return new X509TrustManager() {

			@Override
			public void checkClientTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
				// do nothing					
			}

			@Override
			public void checkServerTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
				// do nothing
			}

			@Override
			public X509Certificate[] getAcceptedIssuers() {
				return null;
			}
		};
	}
	
	public static String pbeEncrypt(byte [] bytes, String password, PBEAlgorithm algorithm) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidParameterSpecException, IOException {
		return pbeEncrypt(bytes, password, algorithm, false);
	}
	
	public static String pbeEncrypt(byte [] bytes, String password, PBEAlgorithm algorithm, boolean useBase64Url) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IOException, IllegalBlockSizeException, BadPaddingException, InvalidParameterSpecException {
		SecretKeyFactory factory = SecretKeyFactory.getInstance(algorithm.getAlgorithm());

		// we generate a new salt for each encryption
		byte [] salt = new byte[8];
		new SecureRandom().nextBytes(salt);
		
		KeySpec keySpec = new PBEKeySpec(password.toCharArray());
		SecretKey key = factory.generateSecret(keySpec);
		Cipher encryptionCipher = Cipher.getInstance(algorithm.getAlgorithm());
		encryptionCipher.init(Cipher.ENCRYPT_MODE, key, new PBEParameterSpec(salt, 1024));
		
		// we must store the parameters for the key in the resulting data as we need it to decrypt correctly
		// for DES this is not necessary for AES it is
		byte [] parameters = encryptionCipher.getParameters().getEncoded();
		byte [] encrypted = encryptionCipher.doFinal(bytes);
		Base64Encoder transcoder = new Base64Encoder();
		transcoder.setUseBase64Url(useBase64Url);
		transcoder.setBytesPerLine(0);
		byte [] encoded = IOUtils.toBytes(TranscoderUtils.transcodeBytes(
			IOUtils.wrap(encrypted, true), 
			transcoder)
		);
		transcoder = new Base64Encoder();
		transcoder.setUseBase64Url(useBase64Url);
		transcoder.setBytesPerLine(0);
		byte [] encodedParameters = IOUtils.toBytes(TranscoderUtils.transcodeBytes(
			IOUtils.wrap(parameters, true), 
			transcoder)
		);
		return new String(encodedParameters, "ASCII") + "$" + new String(encoded, "ASCII");
	}
	
	public static byte [] pbeDecrypt(String encrypted, String password, PBEAlgorithm algorithm) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException {
		return pbeDecrypt(encrypted, password, algorithm, false);
	}
	
	public static byte [] pbeDecrypt(String encrypted, String password, PBEAlgorithm algorithm, boolean useBase64Url) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IOException, IllegalBlockSizeException, BadPaddingException {
		SecretKeyFactory factory = SecretKeyFactory.getInstance(algorithm.getAlgorithm());
		KeySpec keySpec = new PBEKeySpec(password.toCharArray());
		SecretKey key = factory.generateSecret(keySpec);
		
		// we want to extract the encoded parameters
		int indexOf = encrypted.indexOf('$');
		if (indexOf < 0) {
			throw new IllegalArgumentException("Expecting an IV at the beginning of the encrypted data");
		}
		
		String encodedParameters = encrypted.substring(0, indexOf);
		encrypted = encrypted.substring(indexOf + 1);
		
		Cipher decryptionCipher = Cipher.getInstance(algorithm.getAlgorithm());

		Base64Decoder transcoder = new Base64Decoder();
		transcoder.setUseBase64Url(useBase64Url);
		
		byte [] decoded = IOUtils.toBytes(TranscoderUtils.transcodeBytes(
			IOUtils.wrap(encrypted.getBytes("ASCII"), true), 
			transcoder)
		);
		
		byte [] parameters = IOUtils.toBytes(TranscoderUtils.transcodeBytes(
			IOUtils.wrap(encodedParameters.getBytes("ASCII"), true), 
			transcoder)
		);
		
		AlgorithmParameters algorithmParameters = AlgorithmParameters.getInstance(algorithm.getAlgorithm());
		algorithmParameters.init(parameters);
		
		decryptionCipher.init(Cipher.DECRYPT_MODE, key, algorithmParameters);
		return decryptionCipher.doFinal(decoded);
	}
	
	/**
	 * Use only for testing purposes!
	 * @param type
	 * @return
	 * @throws KeyManagementException
	 * @throws NoSuchAlgorithmException
	 */
	public static SSLSocketFactory createTrustAllSocketFactory(SSLContextType type) throws KeyManagementException, NoSuchAlgorithmException {
		SSLContext context = SSLContext.getInstance(type.toString());
		TrustManager[] trustAllCerts = new TrustManager[] { createTrustAllManager() };
		context.init(null, trustAllCerts, null);
		return context.getSocketFactory();
	}

	public static KeyManager [] createKeyManagers(KeyStore keyStore, String password) throws NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException {
		KeyManagerFactory factory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
		factory.init(keyStore, (password == null ? "" : password).toCharArray());
		return factory.getKeyManagers();
	}
	
	public static KeyManager [] limitKeyManagers(KeyManager [] keyManagers, String alias) {
		KeyManager [] result = new KeyManager[keyManagers.length];
		for (int i = 0; i < keyManagers.length; i++) {
			if (keyManagers[i] instanceof X509KeyManager)
				result[i] = new AliasKeyManager((X509KeyManager) keyManagers[i], alias);
			else
				result[i] = keyManagers[i];
		}
		return keyManagers;
	}
	
	public static TrustManager [] createTrustManagers(KeyStore trustStore) throws NoSuchAlgorithmException, KeyStoreException {
		TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		factory.init(trustStore);
		return factory.getTrustManagers();
	}
	
	public static SSLContext createSSLContext(SSLContextType type, KeyManager [] keyManagers, TrustManager [] trustManagers) throws KeyManagementException, NoSuchAlgorithmException {
		SSLContext context = SSLContext.getInstance(type.name());
		context.init(keyManagers, trustManagers, new SecureRandom());
		return context;
	}
	
	public static class SavingTrustManager implements X509TrustManager {
		
		private X509TrustManager parent;
		
		private X509Certificate[] chain;
		
		public SavingTrustManager(X509TrustManager parent) {
			this.parent = parent;
		}
		
		@Override
		public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
			parent.checkClientTrusted(chain, authType);
		}

		@Override
		public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
			this.chain = chain;
			parent.checkServerTrusted(chain, authType);
		}
		
		public X509Certificate[] getChain() {
			return chain;
		}

		@Override
		public X509Certificate[] getAcceptedIssuers() {
			return parent.getAcceptedIssuers();
		}
	}
	
	/**
	 * This method allows you to get the certificate chain for a certain host
	 * This allows you to inspect it and if necessary, add it to the keystore 
	 */
	public static X509Certificate [] getChain(String host, int port, SSLContextType type) throws NoSuchAlgorithmException, KeyManagementException, UnknownHostException, IOException {
		SSLContext context = SSLContext.getInstance(type.toString());
		// this throws a "TrustManagerFactoryImpl is not initialized" in some cases
		// besides to store the cert, we want to trust everything
//		TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
//		X509TrustManager defaultTrustManager = (X509TrustManager) tmf.getTrustManagers()[0];
		X509TrustManager defaultTrustManager = createTrustAllManager();
		SavingTrustManager trustManager = new SavingTrustManager(defaultTrustManager);
		context.init(null, new TrustManager [] { trustManager }, null);
		SSLSocketFactory factory = context.getSocketFactory();
		SSLSocket socket = (SSLSocket)factory.createSocket(host, port);
		socket.setSoTimeout(10000);
		try {
			socket.startHandshake();
			socket.close();
		}
		catch (SSLException e) {
			// do nothing, this just means the certificate isn't trusted yet which is likely why you are running this in the first place
		}
		return trustManager.getChain();
	}
	
	public static Map<String, String> getParts(X500Principal principal) {
		Map<String, String> parts = new HashMap<String, String>();
		for (String part : principal.getName().split("[\\s]*,[\\s]*")) {
			String [] stringBits = part.split("[\\s]*=[\\s]*");
			parts.put(stringBits[0], stringBits.length > 1 ? stringBits[1] : null);
		}
		return parts;
	}
	
	public static X509Certificate parseCertificate(InputStream input) throws CertificateException {
		CertificateFactory factory = CertificateFactory.getInstance("X.509");
		return (X509Certificate) factory.generateCertificate(input);
	}
	
	public static X509Certificate[] parseCertificateChain(InputStream input) throws CertificateException {
		CertificateFactory factory = CertificateFactory.getInstance("X.509");
		CertPath path = factory.generateCertPath(input);
		X509Certificate[] chain = (X509Certificate[]) path.getCertificates().toArray(new X509Certificate[1]);
		return chain;
	}
	
	/**
	 * As read here: http://docs.oracle.com/javase/7/docs/technotes/guides/security/certpath/CertPathProgGuide.html
	 * CertPath.getCertificates() returns:
	 * The returned List and the Certificates contained within it are immutable, in order to protect the contents of the CertPath object. 
	 * The ordering of the certificates returned depends on the type. 
	 * By convention, the certificates in a CertPath object of type X.509 are ordered starting with the target certificate and ending with a certificate issued by the trust anchor. 
	 * That is, the issuer of one certificate is the subject of the following one. The certificate representing the TrustAnchor should not be included in the certification path. 
	 * Unvalidated X.509 CertPaths may not follow this convention. 
	 * PKIX CertPathValidators will detect any departure from these conventions that cause the certification path to be invalid and throw a CertPathValidatorException.
	 * 
	 * This means by convention (not enforced) getCertificates().get(0) will be the user certificate followed by any intermediates and eventually the CA
	 */
	public static CertPath generateCertificatePath(Certificate...certificates) throws CertificateException {
		return CertificateFactory.getInstance("X.509").generateCertPath(Arrays.asList(certificates));
	}
	
	public static X509Certificate decodeCertificate(String content) throws IOException, CertificateException {
		// replace potential BEGIN and END certificate stuff
		content = content.replaceAll("---.*?---", "");
		ReadableContainer<ByteBuffer> decoded = TranscoderUtils.transcodeBytes(IOUtils.wrap(content.getBytes(), true), new Base64Decoder());
		return parseCertificate(IOUtils.toInputStream(decoded));
	}
	
	public static void encodeCertificate(X509Certificate certificate, Writer output) throws CertificateEncodingException, IOException {
		output.write("-----BEGIN CERTIFICATE-----\n".toCharArray());
		ReadableContainer<ByteBuffer> encoded = TranscoderUtils.transcodeBytes(IOUtils.wrap(certificate.getEncoded(), true), new Base64Encoder());
		output.write(IOUtils.toString(IOUtils.wrapReadable(encoded, Charset.forName("ASCII")))
			.replaceAll("([\\w/+=]{77})", "$1\n")
			.toCharArray());
		output.write("\n-----END CERTIFICATE-----\n".toCharArray());
	}
	
	public static void encodePKCS8(PrivateKey key, Writer output) throws IOException {
		// you can verify the written key using openssl:
		// $ openssl pkcs8 -inform PEM -nocrypt -in priv.pem -outform DER -out openssl.key
		output.write("-----BEGIN PRIVATE KEY-----\n".toCharArray());
		ReadableContainer<ByteBuffer> encoded = TranscoderUtils.transcodeBytes(IOUtils.wrap(key.getEncoded(), true), new Base64Encoder());
		output.write(IOUtils.toString(IOUtils.wrapReadable(encoded, Charset.forName("ASCII")))
			.replaceAll("([\\w/+=]{77})", "$1\n")
			.toCharArray());
		output.write("\n-----END PRIVATE KEY-----\n".toCharArray());
	}
	
	public static void writePublic(PublicKey key, OutputStream output) throws IOException {
		output.write(key.getEncoded());
	}
	
	/**
	 * Allows you to decode encoded content like keys, certificates,...
	 * These decoded parts can then be given to for example parsePKCS8
	 */
	public static byte [] decode(String content) {
		content = content.replaceAll("---.*[\n]*", "");
		try {
			return IOUtils.toBytes(TranscoderUtils.transcodeBytes(IOUtils.wrap(content.getBytes(), true), new Base64Decoder()));
		}
		catch(IOException e) {
			throw new RuntimeException(e);
		}
	}
	
	public static PublicKey parsePublic(KeyPairType type, byte [] container) throws InvalidKeySpecException, NoSuchAlgorithmException {
		X509EncodedKeySpec spec = new X509EncodedKeySpec(container);
		KeyFactory keyFactory = KeyFactory.getInstance(type.toString());
		return keyFactory.generatePublic(spec);
	}
	
	/**
	 * This expects the decoded version
	 */
	public static KeyPair parsePKCS8(KeyPairType type, byte [] container) throws NoSuchAlgorithmException, InvalidKeySpecException {
		KeyFactory keyFactory = KeyFactory.getInstance(type.toString());
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(container);
		PrivateKey privKey = keyFactory.generatePrivate(spec);
		PublicKey pubKey = keyFactory.generatePublic(spec);
		return new KeyPair(pubKey, privKey);
	}
	
	public static PrivateKey parsePKCS8Private(KeyPairType type, byte [] container) throws NoSuchAlgorithmException, InvalidKeySpecException {
		KeyFactory keyFactory = KeyFactory.getInstance(type.toString());
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(container);
		return keyFactory.generatePrivate(spec);
	}
	
	public static KeyPair generateKeyPair(KeyPairType type, int keySize) throws NoSuchAlgorithmException {
		KeyPairGenerator generator = KeyPairGenerator.getInstance(type.toString());
		generator.initialize(keySize);
		return generator.generateKeyPair();
	}

	public static List<String> getProviders() {
		List<String> providers = new ArrayList<String>();
		for (Provider provider : Security.getProviders())
			providers.add(provider.getName());
		return providers;
	}
	
	public static Set<String> getAlgorithms(ServiceType type) {
		return Security.getAlgorithms(type.getName());
	}
	
	// formatted according to http://www.ietf.org/rfc/rfc3490.txt
	public static String encodeAce(String domain) {
		return IDN.toASCII(domain.trim()).toLowerCase();
	}
	
	public static String encodeMac(byte[] key, InputStream content, String algorithm) throws NoSuchAlgorithmException, IllegalStateException, IOException, InvalidKeyException {
		Mac mac = Mac.getInstance(algorithm);
		SecretKeySpec secretKeySpec = new SecretKeySpec(key, algorithm);
		mac.init(secretKeySpec);
		byte [] bytes = new byte[102400];
		int read = 0;
		while ((read = content.read(bytes)) > 0) {
			mac.update(bytes, 0, read);
		}
		return encodeDigest(mac.doFinal());
	}
	
	public static String encodeMac(SecretKey key, InputStream content, String algorithm) throws NoSuchAlgorithmException, IllegalStateException, IOException, InvalidKeyException {
		Mac mac = Mac.getInstance(algorithm);
		mac.init(key);
		byte [] bytes = new byte[102400];
		int read = 0;
		while ((read = content.read(bytes)) > 0) {
			mac.update(bytes, 0, read);
		}
		return encodeDigest(mac.doFinal());
	}
	
	public static X500Principal createX500Principal(String commonName, String organisation, String organisationalUnit, String locality, String state, String country) {
		String name = "CN=" + commonName;
		if (organisation != null)
			name += ", O=" + organisation;
		if (organisationalUnit != null)
			name += ", OU=" + organisationalUnit;
		if (locality != null)
			name += ", L=" + locality;
		if (state != null)
			name += ", S=" + state;
		if (country != null)
			name += ", C=" + country;
		return new X500Principal(name);
	}
	
	public static void extract(OutputStream output, KeyStore store, Map<String, String> passwords, String certExtension, String keyExtension) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException {
		if (passwords == null)
			passwords = new HashMap<String, String>();
		ZipOutputStream zip = new ZipOutputStream(output);
		Enumeration<String> aliases = store.aliases();
		while (aliases.hasMoreElements()) {
			String alias = aliases.nextElement();
			byte [] encoded;
			String extension;
			if (store.isCertificateEntry(alias)) {
				Certificate cert = store.getCertificate(alias);
				encoded = cert.getEncoded();
				extension = certExtension;
			}
			else if (store.isKeyEntry(alias)) {
				Key key = store.getKey(alias, (passwords.containsKey(alias) ? passwords.get(alias) : "").toCharArray());
				Certificate [] chain = store.getCertificateChain(alias);
				for (int i = 0; i < chain.length; i++) {
					ZipEntry entry = new ZipEntry(alias.replaceAll("[^\\w]+", "_") + ".chain" + i + "." + certExtension);
					encoded = chain[i].getEncoded();
					entry.setSize(encoded.length);
					zip.putNextEntry(entry);
					zip.write(encoded);
				}				
				encoded = key.getEncoded();
				extension = keyExtension;
			}
			else
				throw new RuntimeException("Unknown type in keystore: " + alias);
			
			ZipEntry entry = new ZipEntry(alias.replaceAll("[^\\w]+", "_") + "." + extension);
			entry.setSize(encoded.length);
			zip.putNextEntry(entry);
			zip.write(encoded);
		}
		zip.finish();
	}
	
	public static BigInteger generateSerialId() {
		SecureRandom random = new SecureRandom();
		byte [] bytes = new byte[16];
		random.nextBytes(bytes);
		return new BigInteger(bytes);
	}
	
	/**
	 * Sign the content in the container with the given key
	 * @throws IOException 
	 */
	public static Signature sign(InputStream dataToSign, PrivateKey key, SignatureType type) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException {
		Signature signature = Signature.getInstance(type.name());
		signature.initSign(key);
		byte [] content = new byte[102400];
		int read = 0;
		while ((read = dataToSign.read(content)) > 0)
			signature.update(content, 0, read);
		return signature;
	}
	
	public static void signXml(Element elementToSign, PrivateKey key, X509Certificate certificate, DigestMethod digestMethod, SignatureMethod signatureMethod) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, MarshalException, XMLSignatureException {
		XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");
		DigestMethod digestMethodInstance = factory.newDigestMethod(digestMethod == null ? DigestMethod.SHA1 : digestMethod.getAlgorithm(), null);
		List<Transform> transforms = new ArrayList<Transform>();
		transforms.add(factory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null));

		// we want to sign the whole document, we indicate this with ""
//		Reference reference = factory.newReference("", digestMethodInstance, transforms, null, null);
		
		String id = null;
		if (elementToSign.hasAttribute("id")) {
			id = elementToSign.getAttribute("id");
			elementToSign.setIdAttribute("id", true);
		}
		else if (elementToSign.hasAttribute("Id")) {
			id = elementToSign.getAttribute("Id");
			elementToSign.setIdAttribute("Id", true);
		}
		else if (elementToSign.hasAttribute("ID")) {
			id = elementToSign.getAttribute("ID");
			elementToSign.setIdAttribute("ID", true);
		}
		if (id == null) {
			id = "id" + UUID.randomUUID().toString().replace("-", "");
			elementToSign.setAttribute("ID", id);
			elementToSign.setIdAttribute("ID", true);
		}
		else {
			elementToSign.setIdAttribute("ID", true);
		}
		Reference reference = factory.newReference("#" + id, digestMethodInstance, transforms, null, null);
		
		// create the signer information
		CanonicalizationMethod canonicalizationMethod = factory.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null);
		SignatureMethod signatureMethodInstance = factory.newSignatureMethod(signatureMethod == null ? SignatureMethod.RSA_SHA1 : signatureMethod.getAlgorithm(), null);
		SignedInfo signedInfo = factory.newSignedInfo(canonicalizationMethod, signatureMethodInstance, Arrays.asList(reference));
		
		// create the key info information
		KeyInfoFactory keyInfoFactory = factory.getKeyInfoFactory();
		List keyList = new ArrayList();
		// not necessary
//		keyList.add(certificate.getSubjectX500Principal().getName());
		keyList.add(certificate);
		X509Data x509Data = keyInfoFactory.newX509Data(keyList);
		KeyInfo keyInfo = keyInfoFactory.newKeyInfo(Arrays.asList(x509Data));
		
		// create signature
		DOMSignContext signatureContext = new DOMSignContext(key, elementToSign);
		XMLSignature signature = factory.newXMLSignature(signedInfo, keyInfo);
		
		signature.sign(signatureContext);
	}
	
	public static boolean verifyXml(Element element, PublicKey key) throws MarshalException {
		return verifyXml(element, "Signature", key);
	}
	// the pathToSignature must point to the entire signature which contains a number of elements 
	public static boolean verifyXml(Element element, String pathToSignature, PublicKey key) throws MarshalException {
		XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");
		String[] parts = pathToSignature.replaceFirst("^[/]+$", "").split("/");
		Element signatureElement = element;
		search: for (String part : parts) {
			NodeList childNodes = signatureElement.getChildNodes();
			for (int i = 0; i < childNodes.getLength(); i++) {
				Node item = childNodes.item(i);
				if (item instanceof Element && ((Element) item).getLocalName().equalsIgnoreCase(part)) {
					signatureElement = (Element) item;
					continue search;
				}
			}
			throw new IllegalArgumentException("Could not resolve '" + part + "' of signature path '" + pathToSignature + "'");
		}
		DOMValidateContext validationContext = new DOMValidateContext(key, element);
		// the signature contains a reference to the part it is signing
		// the reference is resolved using an id attribute (expected way of writing is ID apparently though this seems flexible)
		// at some point java made id attributes more strict: it must not only be named id (in its various forms) but it must also be defined as an id field in the accompanying definition of the file
		// if however your definition is not correct (or simply not available), java can't deduce that it is an id field. we can explicitly set it as such
		// note that currently we assume the element you pass in is the root of our signed content, otherwise we need to tweak this code to be recursive
		if (element.hasAttribute("id")) {
			element.setIdAttribute("id", true);	
		}
		else if (element.hasAttribute("Id")) {
			element.setIdAttribute("Id", true);	
		}
		else if (element.hasAttribute("ID")) {
			element.setIdAttribute("ID", true);
		}
		// This property controls whether or not the digested Reference objects will cache the dereferenced content and pre-digested input for subsequent retrieval via the Reference.getDereferencedData and Reference.getDigestInputStream methods. The default value if not specified is Boolean.FALSE.
//		validationContext.setProperty("javax.xml.crypto.dsig.cacheReference", true);
		XMLSignature signature = factory.unmarshalXMLSignature(new DOMStructure(signatureElement));
		try {
			if (signature.validate(validationContext)) {
				// not sure if this is necessary?
	//			boolean signatureValid = signature.getSignatureValue().validate(validationContext);
	//			for (Object reference : signature.getSignedInfo().getReferences()) {
	//				boolean referenceValid = ((Reference) reference).validate(validationContext);
	//			}
				return true;
			}
			else {
				return false;
			}
		}
		// if the signature is simply wrong vs the cert (e.g. different bitsize), an exception is thrown
		catch (XMLSignatureException e) {
			return false;
		}
	}
	
	public static boolean verify(InputStream dataToVerify, byte [] signatureToVerify, PublicKey key, SignatureType type) throws SignatureException, InvalidKeyException, NoSuchAlgorithmException, IOException {
		Signature signature = Signature.getInstance(type.name());
		signature.initVerify(key);
		byte [] content = new byte[102400];
		int read = 0;
		while ((read = dataToVerify.read(content)) > 0)
			signature.update(content, 0, read);
		return signature.verify(signatureToVerify);
	}
	
	// 12 rounds already takes on average 300ms for one calculation on an i7...
	public static String bcryptHash(String string, Integer rounds) {
		if (rounds == null) {
			rounds = 12;
		}
		return BCrypt.hashpw(string, BCrypt.gensalt(rounds));
	}
	
	public static boolean bcryptCheck(String string, String hash) {
		return BCrypt.checkpw(string, hash);
	}
	
	public static String hash(String string, DigestAlgorithm algorithm) throws NoSuchAlgorithmException, IOException {
		if (algorithm == DigestAlgorithm.BCRYPT) {
			return bcryptHash(string, null);
		}
		else {
			byte[] digest = digest(new ByteArrayInputStream(string.getBytes(Charset.forName("UTF-8"))), algorithm);
			return IOUtils.toString(new HexReadableCharContainer(IOUtils.wrap(digest, true)));
		}
	}
	
	public static boolean check(String string, String hashed, DigestAlgorithm algorithm) throws NoSuchAlgorithmException, IOException {
		if (algorithm == DigestAlgorithm.BCRYPT) {
			return bcryptCheck(string, hashed);
		}
		else {
			byte[] digest = digest(new ByteArrayInputStream(string.getBytes(Charset.forName("UTF-8"))), algorithm);
			String result = IOUtils.toString(new HexReadableCharContainer(IOUtils.wrap(digest, true)));
			return hashed.equals(result);
		}
	}
	
	public static byte [] digest(InputStream input, DigestAlgorithm algorithm) throws NoSuchAlgorithmException, IOException {
		DigestGenerator generator = new DigestGenerator(algorithm);
		IOUtils.copyBytes(IOUtils.wrap(input), generator);
		generator.close();
		return generator.getDigestsByOID().get(algorithm.getOID());
	}
	
	public static String encodeDigest(byte [] digest) {
		StringBuilder string = new StringBuilder();
		for (int i = 0; i < digest.length; ++i) {
			string.append(Integer.toHexString((digest[i] & 0xFF) | 0x100).substring(1,3));
		}
		return string.toString();
	}
	
	public static class DigestGenerator implements WritableContainer<ByteBuffer> {

		private Map<DigestAlgorithm, Container<ByteBuffer>> digested = new HashMap<DigestAlgorithm, Container<ByteBuffer>>();
		private WritableContainer<ByteBuffer> combined;
		private boolean closed = false;
		
		public DigestGenerator(DigestAlgorithm...algorithms) throws NoSuchAlgorithmException {
			List<Container<ByteBuffer>> byteContainers = new ArrayList<Container<ByteBuffer>>();
			for (int i = 0; i < algorithms.length; i++) {
				// not all algorithms can be found by their oid
				// possibly related to http://bugs.java.com/bugdatabase/view_bug.do?bug_id=6655774?
				MessageDigest instance;
				try {
					instance = MessageDigest.getInstance(algorithms[i].getOID());
				}
				catch (NoSuchAlgorithmException e) {
					// try by the actual name
					instance = MessageDigest.getInstance(algorithms[i].getName());
				}
				Container<ByteBuffer> digest = IOUtils.digest(IOUtils.newByteSink(), instance); 
				byteContainers.add(digest);
				digested.put(algorithms[i], digest);
			}
			combined = IOUtils.multicast(byteContainers);
		}
		
		@Override
		public void close() throws IOException {
			combined.close();
			closed = true;
		}

		@Override
		public void flush() throws IOException {
			combined.flush();
		}

		@Override
		public long write(ByteBuffer source) throws IOException {
			return combined.write(source);
		}
		
		public Map<String, byte[]> getDigestsByOID() throws IOException {
			Map<String, byte[]> digests = new HashMap<String, byte[]>();
			if (closed) {
				for (DigestAlgorithm algorithm : digested.keySet())
					digests.put(algorithm.getOID(), IOUtils.toBytes(digested.get(algorithm)));
			}
			return digests;
		}
	}
	
    public static boolean isSelfSigned(X509Certificate cert) throws CertificateException, NoSuchAlgorithmException, NoSuchProviderException {
		try {
			// try to verify certificate signature with its own public key
			PublicKey key = cert.getPublicKey();
			cert.verify(key);
			return true;
		}
		catch (SignatureException sigEx) {
			// invalid signature: not self-signed
			return false;
		}
		catch (InvalidKeyException keyEx) {
			// invalid key: not self-signed
			return false;
		}
    }
    
	public static X509Certificate [] getRootCertificates(X509Certificate...certificates) throws CertificateException, NoSuchAlgorithmException, NoSuchProviderException {
		List<X509Certificate> result = new ArrayList<X509Certificate>();
		for (X509Certificate certificate : certificates) {
			if (SecurityUtils.isSelfSigned(certificate)) {
				result.add(certificate);
			}
		}
		return result.toArray(new X509Certificate[result.size()]);
	}
	
	public static X509Certificate [] getIntermediateCertificates(X509Certificate...certificates) throws CertificateException, NoSuchAlgorithmException, NoSuchProviderException {
		List<X509Certificate> result = new ArrayList<X509Certificate>();
		for (X509Certificate certificate : certificates) {
			if (!SecurityUtils.isSelfSigned(certificate)) {
				result.add(certificate);
			}
		}
		return result.toArray(new X509Certificate[result.size()]);
	}
	
	public static List<X509Certificate> orderChain(List<X509Certificate> certificates) throws CertificateException, NoSuchAlgorithmException, NoSuchProviderException {
		List<X509Certificate> result = new ArrayList<X509Certificate>();
		X509Certificate[] rootCertificates = getRootCertificates(certificates.toArray(new X509Certificate[0]));
		if (rootCertificates.length == 0) {
			throw new IllegalArgumentException("No root certificate found");
		}
		else if (rootCertificates.length > 1) {
			throw new IllegalArgumentException("Too many root certificates found: " + rootCertificates.length);
		}
		result.add(rootCertificates[0]);
		int lastSize = result.size();
		while (result.size() != certificates.size()) {
			for (X509Certificate certificate : certificates) {
				if (certificate.equals(rootCertificates[0])) {
					continue;
				}
				try {
					certificate.verify(result.get(result.size() - 1).getPublicKey());
					result.add(certificate);
				}
				catch (Exception e) {
					// ignore
				}
			}
			if (result.size() == lastSize) {
				throw new IllegalArgumentException("Broken chain");
			}
			lastSize = result.size();
		}
		Collections.reverse(result);
		return result;
	}
}
