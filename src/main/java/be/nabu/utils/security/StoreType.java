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

package be.nabu.utils.security;

public enum StoreType {
	JKS("JKS", null, "application/x-java-keystore"),
	PKCS12("PKCS12", "BC", "application/x-pkcs12"),
	JCEKS("JCEKS", null, "application/x-java-jceks");
	// we store it in a jks store
	// forgot that jwk does not have certs in general, just keys
//	JWK("JKS", null, "application/jwk+json");
	
	private String alias, provider, contentType;
	
	private StoreType(String alias, String provider, String contentType) {
		this.alias = alias;
		this.provider = provider;
		this.contentType = contentType;
	}
	public String getAlias() {
		return alias;
	}
	public String getProvider() {
		return provider;
	}
	public String getContentType() {
		return contentType;
	}
	public static StoreType findByContentType(String contentType) {
		for (StoreType type : values()) {
			if (type.getContentType().equalsIgnoreCase(contentType))
				return type;
		}
		return null;
	}
}