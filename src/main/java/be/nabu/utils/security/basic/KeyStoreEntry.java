package be.nabu.utils.security.basic;

import be.nabu.utils.security.api.KeyStoreEntryType;

public interface KeyStoreEntry {
	public KeyStoreEntryType getType();
	public byte [] getContent();
	public String getPassword();
}
