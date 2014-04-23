package be.nabu.utils.security.api;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.crypto.SecretKey;

public interface ManagedKeyStore {
	
	public void set(String alias, X509Certificate certificate) throws KeyStoreException;
	public void set(String alias, SecretKey secretKey, String password) throws KeyStoreException;
	public void set(String alias, PrivateKey privateKey, X509Certificate [] chain, String password) throws KeyStoreException;

	public PrivateKey getPrivateKey(String alias) throws KeyStoreException;
	public X509Certificate [] getChain(String alias) throws KeyStoreException;
	public X509Certificate getCertificate(String alias) throws KeyStoreException;
	public SecretKey getSecretKey(String alias) throws KeyStoreException;

	public void rename(String oldAlias, String newAlias) throws KeyStoreException;
	public void delete(String alias) throws KeyStoreException;

	public KeyStore getKeyStore();
	public void save();
	
}
