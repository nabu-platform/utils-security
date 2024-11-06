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
