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
