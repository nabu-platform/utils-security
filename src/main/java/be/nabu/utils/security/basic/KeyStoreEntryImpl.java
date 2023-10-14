package be.nabu.utils.security.basic;

import be.nabu.utils.security.api.KeyStoreEntryType;

public class KeyStoreEntryImpl implements KeyStoreEntry {

	private KeyStoreEntryType type;
	private byte [] content;
	private String password;
	
	public KeyStoreEntryImpl() {
		// auto
	}
	
	public KeyStoreEntryImpl(KeyStoreEntryType type, byte[] content, String password) {
		this.type = type;
		this.content = content;
		this.password = password;
	}

	public KeyStoreEntryType getType() {
		return type;
	}
	public void setType(KeyStoreEntryType type) {
		this.type = type;
	}
	public byte[] getContent() {
		return content;
	}
	public void setContent(byte[] content) {
		this.content = content;
	}
	public String getPassword() {
		return password;
	}
	public void setPassword(String password) {
		this.password = password;
	}
	

}
