package be.nabu.utils.security.basic;

import java.util.List;

public interface KeyStorePersistanceManager {
	public void set(String keystoreAlias, String entryAlias, KeyStoreEntry entry);
	public KeyStoreEntry get(String keystoreAlias, String entryAlias);
	public List<String> getAliases(String keystoreAlias);
	public void delete(String keystoreAlias, String entryAlias);
}
