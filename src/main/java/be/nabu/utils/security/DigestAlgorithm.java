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

public enum DigestAlgorithm {
	SHA1("1.3.14.3.2.26", "SHA-1"),
	MD5("1.2.840.113549.2.5", "MD5"),
	SHA256("2.16.840.1.101.3.4.2.1", "SHA-256"),
	SHA384("2.16.840.1.101.3.4.2.2", "SHA-384"),
	SHA512("2.16.840.1.101.3.4.2.3", "SHA-512"),
	SHA224("2.16.840.1.101.3.4.2.4", "SHA-224"),
	GOST3411("1.2.643.2.2.9", "GOST-3411"),
	RIPEMD160("1.3.36.3.2.1", "RIPEMD-160"),
	RIPEMD128("1.3.36.3.2.2", "RIPEMD-128"),
	RIPEMD256("1.3.36.3.2.3", "RIPEMD-256"),
	// bcrypt does not have an official oid? can add BCRYPT13 later on if we need more rounds
	BCRYPT("bcrypt", "BCRYPT")
	// should add support for PBKDF2 as it is fips compliant (possibly only with certain combinations)
	// can use same principle as bcrypt to store everything in the resulting password: https://howtodoinjava.com/security/how-to-generate-secure-password-hash-md5-sha-pbkdf2-bcrypt-examples/#PBKDF2WithHmacSHA1
	;
	
	private String oid;
	private String name;
	
	private DigestAlgorithm(String oid, String name) {
		this.oid = oid;
		this.name = name;
	}
	
	public String getOID() {
		return oid;
	}

	public String getName() {
		return name;
	}
	
}
