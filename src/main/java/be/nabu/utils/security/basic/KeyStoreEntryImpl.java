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
