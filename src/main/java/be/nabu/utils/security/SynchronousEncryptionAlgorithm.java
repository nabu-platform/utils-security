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

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;

public enum SynchronousEncryptionAlgorithm {
	DES_EDE3_CBC(CMSEnvelopedDataGenerator.DES_EDE3_CBC, CMSAlgorithm.DES_EDE3_CBC),
	RC2_CBC(CMSEnvelopedDataGenerator.RC2_CBC, CMSAlgorithm.RC2_CBC),
	IDEA_CBC(CMSEnvelopedDataGenerator.IDEA_CBC, CMSAlgorithm.IDEA_CBC),
	CAST5_CBC(CMSEnvelopedDataGenerator.CAST5_CBC, CMSAlgorithm.CAST5_CBC),
	AES128_CBC(CMSEnvelopedDataGenerator.AES128_CBC, CMSAlgorithm.AES128_CBC),
	AES192_CBC(CMSEnvelopedDataGenerator.AES192_CBC, CMSAlgorithm.AES192_CBC),
	AES256_CBC(CMSEnvelopedDataGenerator.AES256_CBC, CMSAlgorithm.AES256_CBC),
	CAMELLIA128_CBC(CMSEnvelopedDataGenerator.CAMELLIA128_CBC, CMSAlgorithm.CAMELLIA128_CBC),
	CAMELLIA192_CBC(CMSEnvelopedDataGenerator.CAMELLIA192_CBC, CMSAlgorithm.CAMELLIA192_CBC),
	CAMELLIA256_CBC(CMSEnvelopedDataGenerator.CAMELLIA256_CBC, CMSAlgorithm.CAMELLIA256_CBC),
	SEED_CBC(CMSEnvelopedDataGenerator.SEED_CBC, CMSAlgorithm.SEED_CBC),
	DES_EDE3_WRAP(CMSEnvelopedDataGenerator.DES_EDE3_WRAP, CMSAlgorithm.DES_EDE3_WRAP),
	AES128_WRAP(CMSEnvelopedDataGenerator.AES128_WRAP, CMSAlgorithm.AES128_WRAP),
	AES256_WRAP(CMSEnvelopedDataGenerator.AES256_WRAP, CMSAlgorithm.AES256_WRAP),
	CAMELLIA128_WRAP(CMSEnvelopedDataGenerator.CAMELLIA128_WRAP, CMSAlgorithm.CAMELLIA128_WRAP),
	CAMELLIA192_WRAP(CMSEnvelopedDataGenerator.CAMELLIA192_WRAP, CMSAlgorithm.CAMELLIA192_WRAP),
	CAMELLIA256_WRAP(CMSEnvelopedDataGenerator.CAMELLIA256_WRAP, CMSAlgorithm.CAMELLIA256_WRAP),
	SEED_WRAP(CMSEnvelopedDataGenerator.SEED_WRAP, CMSAlgorithm.SEED_WRAP),
	ECDH_SHA1KDF(CMSEnvelopedDataGenerator.ECDH_SHA1KDF, CMSAlgorithm.ECDH_SHA1KDF)
	;
	
	private String oid;
	private ASN1ObjectIdentifier identifier;
	
	private SynchronousEncryptionAlgorithm(String oid, ASN1ObjectIdentifier identifier) {
		this.oid = oid;
		this.identifier = identifier;
	}

	public String getOid() {
		return oid;
	}

	public ASN1ObjectIdentifier getIdentifier() {
		return identifier;
	}
	
}
