package be.nabu.utils.security.api;

import java.io.IOException;
import java.util.List;

import be.nabu.utils.security.StoreType;

/**
 * This allows you to manage multiple keystores and store settings like passwords etc
 * 
 * @author alex
 *
 */
public interface KeyStoreManager {
	
	public List<String> listKeystores() throws IOException;
	public ManagedKeyStore getKeyStore(String alias) throws IOException;
	public ManagedKeyStore createKeyStore(String alias, String password, StoreType type) throws IOException;
	public void deleteKeyStore(String alias) throws IOException;
	
}
