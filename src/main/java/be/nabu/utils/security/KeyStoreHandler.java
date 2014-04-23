package be.nabu.utils.security;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;

import be.nabu.utils.io.IOUtils;
import be.nabu.utils.io.api.ReadableByteContainer;
import be.nabu.utils.io.api.WritableByteContainer;

/**
 * This encapsulates the logic necessary to use a java keystore
 * 
 * @author alex
 *
 */
public class KeyStoreHandler {
	
	public static KeyStoreHandler create(String password, StoreType type) throws NoSuchAlgorithmException, CertificateException, KeyStoreException, NoSuchProviderException, IOException {
		return load(null, password, type);
	}
	
	public static KeyStoreHandler load(ReadableByteContainer input, String password, StoreType type) throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException, NoSuchProviderException {
		KeyStore keystore = type.getProvider() == null ? KeyStore.getInstance(type.getAlias()) : KeyStore.getInstance(type.getAlias(), type.getProvider());
		keystore.load(input == null ? null : IOUtils.toInputStream(input), (password == null ? "" : password).toCharArray());
		return new KeyStoreHandler(keystore);
	}
	
	private KeyStore store;
	
	public KeyStoreHandler(KeyStore store) {
		this.store = store;
	}
	
	public void save(WritableByteContainer output, String password) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		store.store(IOUtils.toOutputStream(output), (password == null ? "" : password).toCharArray());
	}
	
	public void set(String alias, X509Certificate certificate) throws KeyStoreException {
		store.setCertificateEntry(alias, certificate);
	}
	
	public void set(String alias, SecretKey secretKey, String password) throws KeyStoreException {
		store.setKeyEntry(alias, secretKey, (password == null ? "" : password).toCharArray(), null);
	}
	
	public void set(String alias, PrivateKey privateKey, X509Certificate [] chain, String password) throws KeyStoreException {
		store.setKeyEntry(alias, privateKey, (password == null ? "" : password).toCharArray(), chain);
	}
	
	public void rename(String oldAlias, String newAlias, String password) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
		if (store.containsAlias(newAlias))
			throw new KeyStoreException("An entry with the alias '" + newAlias + "' already exists, please choose something else");
		// it's a certificate
		if (store.entryInstanceOf(oldAlias, KeyStore.TrustedCertificateEntry.class))
			store.setCertificateEntry(newAlias, store.getCertificate(oldAlias));
		else {
			char [] pass = (password == null ? "" : password).toCharArray();
			store.setKeyEntry(newAlias, store.getKey(oldAlias, pass), pass, store.getCertificateChain(oldAlias));
		}
		store.deleteEntry(oldAlias);
	}
	
	public void delete(String alias) throws KeyStoreException {
		store.deleteEntry(alias);
	}
	
	public KeyStore getKeyStore() {
		return store;
	}
	
	public List<X509Certificate> getRootCertificates() throws KeyStoreException, InvalidAlgorithmParameterException {
		List<X509Certificate> certificates = new ArrayList<X509Certificate>(); 
		PKIXParameters parameters = new PKIXParameters(store);
		for (TrustAnchor trustAnchor : parameters.getTrustAnchors())
			certificates.add(trustAnchor.getTrustedCert());
		return certificates;
	}
	
	public List<String> getPrivateKeyAliases() throws KeyStoreException {
		Enumeration<String> aliases = store.aliases();
		List<String> result = new ArrayList<String>();
		while (aliases.hasMoreElements()) {
			String alias = aliases.nextElement();
			if (store.entryInstanceOf(alias, KeyStore.PrivateKeyEntry.class))
				result.add(alias);
		}
		return result;
	}
	
	public PrivateKey getPrivateKey(String alias, String password) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
		return (PrivateKey) store.getKey(alias, (password == null ? "" : password).toCharArray());
	}
	
	public SecretKey getSecretKey(String alias, String password) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
		return (SecretKey) store.getKey(alias, (password == null ? "" : password).toCharArray());
	}
	
	public X509Certificate getCertificate(String alias) throws KeyStoreException {
		return (X509Certificate) store.getCertificate(alias);
	}
	
	public Map<String, X509Certificate[]> getPrivateKeys() throws KeyStoreException {
		Map<String, X509Certificate[]> keys = new HashMap<String, X509Certificate[]>();
		Enumeration<String> aliases = store.aliases();
		while (aliases.hasMoreElements()) {
			String alias = aliases.nextElement();
			if (store.entryInstanceOf(alias, KeyStore.PrivateKeyEntry.class))
				keys.put(alias, convertToX509(store.getCertificateChain(alias)));
		}
		return keys;
	}
	
	public boolean containsCertificate(Certificate certificate) throws KeyStoreException {
		return store.getCertificateAlias(certificate) != null;
	}
	
	public Map<String, X509Certificate> getCertificates() throws KeyStoreException {
		Map<String, X509Certificate> certificates = new HashMap<String, X509Certificate>();
		Enumeration<String> aliases = store.aliases();
		while (aliases.hasMoreElements()) {
			String alias = aliases.nextElement();
			if (store.entryInstanceOf(alias, KeyStore.TrustedCertificateEntry.class))
				certificates.put(alias, (X509Certificate) store.getCertificate(alias));
		}
		return certificates;
	}
	
	public Map<String, X509Certificate> getIntermediateCertificates() throws KeyStoreException, InvalidAlgorithmParameterException {
		Map<String, X509Certificate> certificates = getCertificates();
		List<X509Certificate> roots = getRootCertificates();
		Iterator<String> it = certificates.keySet().iterator();
		while(it.hasNext()) {
			if (roots.contains(certificates.get(it.next())))
				it.remove();
		}
		return certificates;
	}
	
	public List<String> getSecretKeys() throws KeyStoreException {
		List<String> keys = new ArrayList<String>();
		Enumeration<String> aliases = store.aliases();
		while (aliases.hasMoreElements()) {
			String alias = aliases.nextElement();
			if (store.entryInstanceOf(alias, KeyStore.SecretKeyEntry.class))
				keys.add(alias);
		}
		return keys;
	}
	
	public SSLSocketFactory createSocketFactory(SSLContextType type) throws NoSuchAlgorithmException, KeyManagementException, UnrecoverableKeyException, KeyStoreException {
		return createContext(type).getSocketFactory();
	}
	
	public SSLContext createContext(SSLContextType type) throws KeyManagementException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
		SSLContext context = SSLContext.getInstance(type.toString());
		// by setting the secure random implementation to "null", the default will be used
		// as per http://docs.oracle.com/javase/6/docs/api/javax/net/ssl/SSLContext.html#init%28javax.net.ssl.KeyManager[],%20javax.net.ssl.TrustManager[],%20java.security.SecureRandom%29
		context.init(getKeyManagers(), getTrustManagers(), null);
		return context;
	}

	public SSLSocketFactory createTrustSocketFactory(SSLContextType type) throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException, UnrecoverableKeyException {
		SSLContext context = SSLContext.getInstance(type.toString());
		context.init(null, getTrustManagers(), null);
		return context.getSocketFactory();
	}
	
	public SSLSocketFactory createKeySocketFactory(SSLContextType type, String alias, String keyPassword) throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException, UnrecoverableKeyException {
		SSLContext context = SSLContext.getInstance(type.toString());
		KeyManager [] keyManagers = getKeyManagers();
		for (int i = 0; i < keyManagers.length; i++) {
			if (keyManagers[i] instanceof X509KeyManager)
				keyManagers[i] = new AliasKeyManager((X509KeyManager) keyManagers[i], alias);
		}
		context.init(keyManagers, null, null);
		return context.getSocketFactory();
	}
	
	public TrustManager[] getTrustManagers() throws NoSuchAlgorithmException, KeyStoreException {
		TrustManagerFactory trustFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		trustFactory.init(store);
		return trustFactory.getTrustManagers();
	}
	
	/**
	 * In general you won't set passwords on the private keys themselves, only on the keystore
	 * Additionally even if you set a password on the private keys it would need to be the same password on all keys I think (at least when you look at the spec of KeyManagerFactory.init())
	 * If cross application security is an issue, use different keystores instead of one keystore with differently passworded keys.
	 */
	public KeyManager[] getKeyManagers() throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
		return getKeyManagers(null);
	}
	
	public KeyManager[] getKeyManagers(String keyPassword) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
		KeyManagerFactory keyFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
		keyFactory.init(store, (keyPassword == null ? "" : keyPassword).toCharArray());
		return keyFactory.getKeyManagers();
	}
	
	private static X509Certificate[] convertToX509(Certificate...certificates) {
		X509Certificate[] result = new X509Certificate[certificates.length];
		for (int i = 0; i < certificates.length; i++) {
			if (!(certificates[i] instanceof X509Certificate))
				throw new ClassCastException("Certificate " + i + " is not a X509 certificate: " + certificates[i].getClass().getName());
			result[i] = (X509Certificate) certificates[i];
		}
		return result;
	}
}
