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
