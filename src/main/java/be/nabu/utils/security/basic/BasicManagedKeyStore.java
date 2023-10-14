package be.nabu.utils.security.basic;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.nio.charset.Charset;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.crypto.SecretKey;
import javax.net.ssl.SSLContext;

import be.nabu.utils.security.KeyStoreHandler;
import be.nabu.utils.security.PBEAlgorithm;
import be.nabu.utils.security.SSLContextType;
import be.nabu.utils.security.SecurityUtils;
import be.nabu.utils.security.StoreType;
import be.nabu.utils.security.api.KeyStoreEntryType;
import be.nabu.utils.security.api.ManagedKeyStore;

public class BasicManagedKeyStore implements ManagedKeyStore {
	
	private KeyStorePersistanceManager persistance;
	private String keystoreAlias;
	private String keystorePassword;
	
	public BasicManagedKeyStore(KeyStorePersistanceManager persistance) {
		this(persistance, null, null);
	}
	
	public BasicManagedKeyStore(KeyStorePersistanceManager persistance, String keystoreAlias, String keystorePassword) {
		this.persistance = persistance;
		this.keystorePassword = keystorePassword;
		this.keystoreAlias = keystoreAlias == null ? "default" : keystoreAlias;
	}
	
	public void set(String alias, X509Certificate certificate) {
		StringWriter writer = new StringWriter();
		try {
			SecurityUtils.encodeCertificate(certificate, writer);
			writer.close();
			persistance.set(keystoreAlias, alias, new KeyStoreEntryImpl(KeyStoreEntryType.CERTIFICATE, writer.toString().getBytes("UTF-8"), null));
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	@Override
	public void set(String alias, SecretKey secretKey, String password) {
		String encoded = SecurityUtils.encodeSecret(secretKey, password);
		persistance.set(keystoreAlias, alias, new KeyStoreEntryImpl(KeyStoreEntryType.SECRET_KEY, encoded.getBytes(Charset.forName("ASCII")), encodePassword(password)));
	}
	
	private String encodePassword(String password) {
		if (password != null && password.trim().isEmpty()) {
			password = null;
		}
		if (keystorePassword != null && !keystorePassword.trim().isEmpty() && password != null) {
			try {
				return SecurityUtils.pbeEncrypt(password.getBytes("UTF-8"), keystorePassword, PBEAlgorithm.AES256);
			}
			catch (Exception e) {
				throw new RuntimeException(e);
			}
		}
		return password;
	}
	
	private String decodePassword(String password) {
		if (password != null && password.trim().isEmpty()) {
			password = null;
		}
		if (keystorePassword != null && !keystorePassword.trim().isEmpty() && password != null) {
			try {
				byte[] pbeDecrypt = SecurityUtils.pbeDecrypt(password, keystorePassword, PBEAlgorithm.AES256);
				return new String(pbeDecrypt, "UTF-8");
			}
			catch (Exception e) {
				throw new RuntimeException(e);
			}
		}
		return password;
	}

	@Override
	public void set(String alias, PrivateKey privateKey, X509Certificate [] chain, String password) {
		try {
			KeyStoreHandler handler = KeyStoreHandler.create(password, StoreType.PKCS12);
			handler.set(alias, privateKey, chain, password);
			ByteArrayOutputStream output = new ByteArrayOutputStream();
			handler.save(output, password);
			output.close();
			persistance.set(keystoreAlias, alias, new KeyStoreEntryImpl(KeyStoreEntryType.PRIVATE_KEY, output.toByteArray(), encodePassword(password)));
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	@Override
	public void rename(String oldAlias, String newAlias) {
		KeyStoreEntry keyStoreEntry = persistance.get(keystoreAlias, oldAlias);
		if (keyStoreEntry == null) {
			throw new IllegalArgumentException("Could not find alias '" + oldAlias + "' in keystore '" + keystoreAlias + "'");
		}
		persistance.set(keystoreAlias, newAlias, keyStoreEntry);
		persistance.delete(keystoreAlias, oldAlias);
	}
	
	@Override
	public String getPassword() {
		return keystorePassword;
	}
	
	@Override
	public String getPassword(String alias) {
		KeyStoreEntry keyStoreEntry = persistance.get(keystoreAlias, alias);
		if (keyStoreEntry == null) {
			throw new IllegalArgumentException("Could not find alias '" + alias + "' in keystore '" + keystoreAlias + "'");
		}
		return decodePassword(keyStoreEntry.getPassword());
	}
	
	@Override
	public void delete(String alias) throws KeyStoreException, IOException {
		persistance.delete(keystoreAlias, alias);
	}
	
	@Override
	public PrivateKey getPrivateKey(String alias) {
		KeyStoreEntry keyStoreEntry = persistance.get(keystoreAlias, alias);
		if (keyStoreEntry == null) {
			throw new IllegalArgumentException("Could not find alias '" + alias + "' in keystore '" + keystoreAlias + "'");
		}
		return getPrivateKey(alias, keyStoreEntry);
	}

	private PrivateKey getPrivateKey(String alias, KeyStoreEntry keyStoreEntry) {
		if (keyStoreEntry.getType() != KeyStoreEntryType.PRIVATE_KEY) {
			throw new IllegalArgumentException("The alias '" + alias + "' is not a private key");
		}
		try {
			String decodedPassword = decodePassword(keyStoreEntry.getPassword());
			KeyStoreHandler handler = KeyStoreHandler.load(new ByteArrayInputStream(keyStoreEntry.getContent()), decodedPassword, StoreType.PKCS12);
			return handler.getPrivateKey(alias, decodedPassword);
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	@Override
	public X509Certificate getCertificate(String alias) throws KeyStoreException {
		KeyStoreEntry keyStoreEntry = persistance.get(keystoreAlias, alias);
		if (keyStoreEntry == null) {
			throw new IllegalArgumentException("Could not find alias '" + alias + "' in keystore '" + keystoreAlias + "'");
		}
		return getCertificate(alias, keyStoreEntry);
	}

	private X509Certificate getCertificate(String alias, KeyStoreEntry keyStoreEntry) {
		if (keyStoreEntry.getType() != KeyStoreEntryType.CERTIFICATE) {
			throw new IllegalArgumentException("The alias '" + alias + "' is not a certificate");
		}
		try {
			return SecurityUtils.decodeCertificate(new String(keyStoreEntry.getContent(), Charset.forName("ASCII")));
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	@Override
	public SecretKey getSecretKey(String alias) throws KeyStoreException {
		KeyStoreEntry keyStoreEntry = persistance.get(keystoreAlias, alias);
		if (keyStoreEntry == null) {
			throw new IllegalArgumentException("Could not find alias '" + alias + "' in keystore '" + keystoreAlias + "'");
		}
		return getSecretKey(alias, keyStoreEntry);
	}

	private SecretKey getSecretKey(String alias, KeyStoreEntry keyStoreEntry) {
		if (keyStoreEntry.getType() != KeyStoreEntryType.SECRET_KEY) {
			throw new IllegalArgumentException("The alias '" + alias + "' is not a secret key");
		}
		return SecurityUtils.decodeSecret(new String(keyStoreEntry.getContent(), Charset.forName("UTF-8")), decodePassword(keyStoreEntry.getPassword()));
	}
	
	@Override
	public void save()  {
		// do nothing, it autosaves
	}
	
	@Override
	public X509Certificate[] getChain(String alias) throws KeyStoreException {
		KeyStoreEntry keyStoreEntry = persistance.get(keystoreAlias, alias);
		if (keyStoreEntry == null) {
			throw new IllegalArgumentException("Could not find alias '" + alias + "' in keystore '" + keystoreAlias + "'");
		}
		return getChain(alias, keyStoreEntry);
	}

	private X509Certificate[] getChain(String alias, KeyStoreEntry keyStoreEntry) {
		if (keyStoreEntry.getType() != KeyStoreEntryType.PRIVATE_KEY) {
			throw new IllegalArgumentException("The alias '" + alias + "' is not a private key");
		}
		try {
			String decodedPassword = decodePassword(keyStoreEntry.getPassword());
			KeyStoreHandler handler = KeyStoreHandler.load(new ByteArrayInputStream(keyStoreEntry.getContent()), decodedPassword, StoreType.PKCS12);
			Certificate [] chain = handler.getKeyStore().getCertificateChain(alias);
			X509Certificate [] certificates = new X509Certificate[chain.length];
			for (int i = 0; i < chain.length; i++) {
				certificates[i] = (X509Certificate) chain[i];
			}
			return certificates;
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public KeyStore getKeyStore() {
		try {
			// get as a keystore, we use jceks to support secret keys
			KeyStoreHandler handler = KeyStoreHandler.create(keystorePassword, StoreType.JCEKS);
			List<String> aliases = persistance.getAliases(keystoreAlias);
			if (aliases != null) {
				for (String alias : aliases) {
					KeyStoreEntry entry = persistance.get(keystoreAlias, alias);
					switch (entry.getType()) {
						case CERTIFICATE:
							handler.set(alias, getCertificate(alias, entry));
						break;
						case PRIVATE_KEY:
							handler.set(alias, getPrivateKey(alias, entry), getChain(alias, entry), decodePassword(entry.getPassword()));
						break;
						case SECRET_KEY:
							handler.set(alias, getSecretKey(alias, entry), decodePassword(entry.getPassword()));
						break;
					}
				}
			}
			return handler.getKeyStore();
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	

	@Override
	public SSLContext newContext(SSLContextType type) throws KeyStoreException {
		try {
			KeyStore keyStore = getKeyStore();
			return SecurityUtils.createSSLContext(type, SecurityUtils.createKeyManagers(getKeyStore(), keystorePassword), SecurityUtils.createTrustManagers(keyStore));
		}
		catch (Exception e) {
			throw new KeyStoreException("Failed to create new context", e);
		} 
	}

}
