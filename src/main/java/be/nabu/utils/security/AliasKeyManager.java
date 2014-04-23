package be.nabu.utils.security;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.net.ssl.X509KeyManager;

/**
 * By default the key manager will determine the alias based on a number of properties
 * However in our case we want to be able to pinpoint a specific alias
 */
public class AliasKeyManager implements X509KeyManager {
	
	private X509KeyManager parent = null;
	private String alias = null;
	
	public AliasKeyManager(X509KeyManager parent, String alias) {
		this.parent = parent;
		this.alias = alias;
	}

	/**
	 * Return the alias we indicated
	 */
	@Override
	public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
		return alias;
	}
	
	/**
	 * Redirect others to the parent implementation
	 */
	@Override
	public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
		return parent.chooseServerAlias(keyType, issuers, socket);
	}
	
	@Override
	public X509Certificate[] getCertificateChain(String alias) {
		return parent.getCertificateChain(alias);
	}
	
	@Override
	public String[] getClientAliases(String keyType, Principal[] issuers) {
		return parent.getClientAliases(keyType, issuers);
	}
	
	@Override
	public PrivateKey getPrivateKey(String alias) {
		return parent.getPrivateKey(alias);
	}
	
	@Override
	public String[] getServerAliases(String keyType, Principal[] issuers) {
		return parent.getServerAliases(keyType, issuers);
	}
}
