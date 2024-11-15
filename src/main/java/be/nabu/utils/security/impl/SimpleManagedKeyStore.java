/*
* Copyright (C) 2014 Alexander Verbruggen
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU Lesser General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public License
* along with this program. If not, see <https://www.gnu.org/licenses/>.
*/

package be.nabu.utils.security.impl;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.crypto.SecretKey;
import javax.net.ssl.SSLContext;

import be.nabu.utils.security.KeyStoreHandler;
import be.nabu.utils.security.SSLContextType;
import be.nabu.utils.security.SecurityUtils;
import be.nabu.utils.security.StoreType;
import be.nabu.utils.security.api.ManagedKeyStore;

public class SimpleManagedKeyStore implements ManagedKeyStore {

	private KeyStoreHandler handler;
	private PasswordHandler passwords;
	
	public SimpleManagedKeyStore(KeyStore store) {
		this(store, new SimplePasswordHandler());
	}
	
	public SimpleManagedKeyStore(KeyStore store, PasswordHandler handler) {
		this.handler = new KeyStoreHandler(store);
		this.passwords = handler;
	}
	
	public SimpleManagedKeyStore() {
		this(StoreType.JKS);
	}
	
	public SimpleManagedKeyStore(StoreType type) {
		this(type, new SimplePasswordHandler());
	}
	
	public SimpleManagedKeyStore(StoreType type, PasswordHandler handler) {
		try {
			this.handler = KeyStoreHandler.create(handler.getKeyStorePassword(), type);
			this.passwords = handler;
		}
		catch (KeyStoreException e) {
			throw new RuntimeException(e);
		}
		catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
		catch (CertificateException e) {
			throw new RuntimeException(e);
		}
		catch (NoSuchProviderException e) {
			throw new RuntimeException(e);
		}
	}
	
	@Override
	public void set(String alias, X509Certificate certificate) throws KeyStoreException {
		handler.set(alias, certificate);
	}

	@Override
	public void set(String alias, SecretKey secretKey, String password) throws KeyStoreException {
		handler.set(alias, secretKey, password);
		passwords.setKeyPassword(alias, password);
	}

	@Override
	public void set(String alias, PrivateKey privateKey, X509Certificate[] chain, String password) throws KeyStoreException {
		handler.set(alias, privateKey, chain, password);
		passwords.setKeyPassword(alias, password);
	}

	@Override
	public PrivateKey getPrivateKey(String alias) throws KeyStoreException {
		try {
			return handler.getPrivateKey(alias, passwords.getKeyPassword(alias));
		}
		catch (UnrecoverableKeyException e) {
			throw new KeyStoreException(e);
		}
		catch (NoSuchAlgorithmException e) {
			throw new KeyStoreException(e);
		}
	}

	@Override
	public X509Certificate[] getChain(String alias) throws KeyStoreException {
		return handler.getPrivateKeys().get(alias);
	}

	@Override
	public X509Certificate getCertificate(String alias) throws KeyStoreException {
		return handler.getCertificate(alias);
	}

	@Override
	public SecretKey getSecretKey(String alias) throws KeyStoreException {
		try {
			return handler.getSecretKey(alias, passwords.getKeyPassword(alias));
		}
		catch (UnrecoverableKeyException e) {
			throw new KeyStoreException(e);
		}
		catch (NoSuchAlgorithmException e) {
			throw new KeyStoreException(e);
		}
	}

	@Override
	public void rename(String oldAlias, String newAlias) throws KeyStoreException {
		try {
			handler.rename(oldAlias, newAlias, passwords.getKeyPassword(oldAlias));
		}
		catch (UnrecoverableKeyException e) {
			throw new KeyStoreException(e);
		}
		catch (NoSuchAlgorithmException e) {
			throw new KeyStoreException(e);
		}
	}

	@Override
	public void delete(String alias) throws KeyStoreException {
		handler.delete(alias);
	}

	@Override
	public KeyStore getKeyStore() {
		return handler.getKeyStore();
	}

	@Override
	public void save() {
		throw new UnsupportedOperationException();
	}

	@Override
	public SSLContext newContext(SSLContextType type) throws KeyStoreException {
		try {
			return SecurityUtils.createSSLContext(type, SecurityUtils.createKeyManagers(handler.getKeyStore(), null), SecurityUtils.createTrustManagers(handler.getKeyStore()));
		}
		catch (Exception e) {
			throw new KeyStoreException("Failed to create new context", e);
		}
	}

}
