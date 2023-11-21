package be.nabu.utils.security.api;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.net.ssl.SSLContext;

import be.nabu.utils.security.KeyStoreHandler;
import be.nabu.utils.security.SSLContextType;
import be.nabu.utils.security.basic.NamedKeyStoreEntry;
import be.nabu.utils.security.impl.NamedKeyStoreEntryImpl;

public interface ManagedKeyStore {
	
	public void set(String alias, X509Certificate certificate) throws KeyStoreException, IOException;
	public void set(String alias, SecretKey secretKey, String password) throws KeyStoreException, IOException;
	public void set(String alias, PrivateKey privateKey, X509Certificate [] chain, String password) throws KeyStoreException, IOException;

	public PrivateKey getPrivateKey(String alias) throws KeyStoreException, IOException;
	public X509Certificate [] getChain(String alias) throws KeyStoreException, IOException;
	public X509Certificate getCertificate(String alias) throws KeyStoreException, IOException;
	public SecretKey getSecretKey(String alias) throws KeyStoreException, IOException;

	public void rename(String oldAlias, String newAlias) throws KeyStoreException, IOException;
	public void delete(String alias) throws KeyStoreException, IOException;

	public void save() throws IOException;
	public SSLContext newContext(SSLContextType type) throws KeyStoreException;
	
	/**
	 * Return the global password for this keystore (if any)
	 */
	public default String getPassword() {
		throw new UnsupportedOperationException();
	}
	
	/**
	 * Return the password for a particular alias (if any)
	 */
	public default String getPassword(String alias) {
		throw new UnsupportedOperationException();
	}
	
	/**
	 * Best effort return it as a keystore
	 * Potentially not possible for non-keystore based implementations
	 */
	public default KeyStore getKeyStore() {
		return null;
	}
	
	/**
	 * When building keyhandler contexts etc, it is easier to use an unsecured keystore, otherwise the private keys can not be accessed for SSL purposes
	 */
	public default KeyStore getUnsecuredKeyStore() {
		return getKeyStore();
	}
	
	/**
	 * List all aliases
	 */
	public default List<String> getAliases() throws KeyStoreException {
		List<String> aliases = new ArrayList<String>();
		KeyStore keyStore = getKeyStore();
		if (keyStore != null) {
			Enumeration<String> aliasList = keyStore.aliases();
			while (aliasList.hasMoreElements()) {
				aliases.add(aliasList.nextElement());
			}
		}
		return aliases;
	}
	
	/**
	 * Get all the private key aliases
	 */
	public default List<String> getPrivateKeyAliases() throws KeyStoreException {
		KeyStore keyStore = getKeyStore();
		if (keyStore != null) {
			KeyStoreHandler handler = new KeyStoreHandler(keyStore);
			return handler.getPrivateKeyAliases();
		}
		return new ArrayList<String>();
	}

	/**
	 * Get the entry type
	 */
	public default KeyStoreEntryType getEntryType(String alias) throws KeyStoreException {
		KeyStore keyStore = getKeyStore();
		if (keyStore != null) {
			if (keyStore.entryInstanceOf(alias, KeyStore.TrustedCertificateEntry.class)) {
				return KeyStoreEntryType.CERTIFICATE;
			}
			else if (keyStore.entryInstanceOf(alias, KeyStore.PrivateKeyEntry.class)) {
				return KeyStoreEntryType.PRIVATE_KEY;
			}
			else if (keyStore.entryInstanceOf(alias, KeyStore.SecretKeyEntry.class)) {
				return KeyStoreEntryType.SECRET_KEY;
			}
		}
		return null;
	}
	
	public default Map<String, X509Certificate> getCertificates() throws KeyStoreException {
		KeyStore keyStore = getKeyStore();
		if (keyStore != null) {
			return new KeyStoreHandler(keyStore).getCertificates();
		}
		return new HashMap<String, X509Certificate>();
	}
	
}
