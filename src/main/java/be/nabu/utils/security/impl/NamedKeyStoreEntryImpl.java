package be.nabu.utils.security.impl;

import be.nabu.utils.security.api.KeyStoreEntryType;
import be.nabu.utils.security.basic.NamedKeyStoreEntry;

public class NamedKeyStoreEntryImpl implements NamedKeyStoreEntry {

	private KeyStoreEntryType type;
	private byte [] content;
	private String password;
	private String alias;
	
	@Override
	public KeyStoreEntryType getType() {
		return type;
	}
	public void setType(KeyStoreEntryType type) {
		this.type = type;
	}
	@Override
	public byte[] getContent() {
		return content;
	}
	public void setContent(byte[] content) {
		this.content = content;
	}
	@Override
	public String getPassword() {
		return password;
	}
	public void setPassword(String password) {
		this.password = password;
	}
	@Override
	public String getAlias() {
		return alias;
	}
	public void setAlias(String alias) {
		this.alias = alias;
	}

}
