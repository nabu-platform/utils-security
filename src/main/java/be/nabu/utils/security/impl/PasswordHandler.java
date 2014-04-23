package be.nabu.utils.security.impl;

public interface PasswordHandler {
	public String getKeyStorePassword();
	public String getKeyPassword(String alias);
	public void setKeyPassword(String alias, String password);
}
