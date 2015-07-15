package be.nabu.utils.security;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Writer;
import java.math.BigInteger;
import java.net.UnknownHostException;
import java.nio.charset.Charset;
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
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

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

import be.nabu.utils.codec.TranscoderUtils;
import be.nabu.utils.codec.impl.Base64Encoder;
import be.nabu.utils.io.IOUtils;
import be.nabu.utils.io.api.ByteBuffer;
import be.nabu.utils.io.api.Container;
import be.nabu.utils.io.api.ReadableContainer;
import be.nabu.utils.io.api.WritableContainer;

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
	
	public static CertPath generateCertificatePath(Certificate...certificates) throws CertificateException {
		return CertificateFactory.getInstance("X.509").generateCertPath(Arrays.asList(certificates));
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
	
	public static PublicKey parsePublic(KeyPairType type, byte [] container) throws InvalidKeySpecException, NoSuchAlgorithmException {
		X509EncodedKeySpec spec = new X509EncodedKeySpec(container);
		KeyFactory keyFactory = KeyFactory.getInstance(type.toString());
		return keyFactory.generatePublic(spec);
	}
	
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
	
	public static boolean verify(InputStream dataToVerify, byte [] signatureToVerify, PublicKey key, SignatureType type) throws SignatureException, InvalidKeyException, NoSuchAlgorithmException, IOException {
		Signature signature = Signature.getInstance(type.name());
		signature.initVerify(key);
		byte [] content = new byte[102400];
		int read = 0;
		while ((read = dataToVerify.read(content)) > 0)
			signature.update(content, 0, read);
		return signature.verify(signatureToVerify);
	}
	
	public static class DigestGenerator implements WritableContainer<ByteBuffer> {

		private Map<DigestAlgorithm, Container<ByteBuffer>> digested = new HashMap<DigestAlgorithm, Container<ByteBuffer>>();
		private WritableContainer<ByteBuffer> combined;
		private boolean closed = false;
		
		public DigestGenerator(DigestAlgorithm...algorithms) throws NoSuchAlgorithmException {
			List<Container<ByteBuffer>> byteContainers = new ArrayList<Container<ByteBuffer>>();
			for (int i = 0; i < algorithms.length; i++) {
				Container<ByteBuffer> digest = IOUtils.digest(IOUtils.newByteSink(), MessageDigest.getInstance(algorithms[i].toString())); 
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
	
}
