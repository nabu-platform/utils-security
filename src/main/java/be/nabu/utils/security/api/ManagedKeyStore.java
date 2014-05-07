package be.nabu.utils.security.api;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.crypto.SecretKey;

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

	public KeyStore getKeyStore();
	public void save() throws IOException;
	
}
