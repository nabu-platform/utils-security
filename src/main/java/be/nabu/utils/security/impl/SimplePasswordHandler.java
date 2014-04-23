package be.nabu.utils.security.impl;

import java.util.HashMap;
import java.util.Map;

public class SimplePasswordHandler implements PasswordHandler {

	private String keystorePassword;
	private Map<String, String> passwords = new HashMap<String, String>();
	
	public SimplePasswordHandler() {
		// remains null
	}
	
	public SimplePasswordHandler(String keystorePassword) {
		this.keystorePassword = keystorePassword;
	}
	
	@Override
	public String getKeyStorePassword() {
		return keystorePassword;
	}

	@Override
	public String getKeyPassword(String alias) {
		return passwords.get(alias);
	}

	@Override
	public void setKeyPassword(String alias, String password) {
		passwords.put(alias, password);
	}

}
