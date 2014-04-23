package be.nabu.utils.security.api;

import java.util.List;

import be.nabu.utils.security.StoreType;

/**
 * This allows you to manage multiple keystores and store settings like passwords etc
 * 
 * @author alex
 *
 */
public interface KeyStoreManager {
	
	public List<String> listKeystores();
	public ManagedKeyStore getKeyStore(String alias);
	public ManagedKeyStore createKeyStore(String alias, String password, StoreType type);
	public void deleteKeyStore(String alias);
	
}
