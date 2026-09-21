/*
* Copyright (C) 2014 Alexander Verbruggen
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU Lesser General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*/

package be.nabu.utils.security;

import junit.framework.TestCase;

public class TestEncryptionXmlAdapter extends TestCase {

	public void testAes256RoundTrip() throws Exception {
		EncryptionXmlAdapter adapter = new EncryptionXmlAdapter();
		String encrypted = adapter.marshal("configuration secret");
		assertTrue(encrypted.startsWith("${encrypted:"));
		assertTrue(encrypted.indexOf('$') >= 0);
		assertEquals("configuration secret", adapter.unmarshal(encrypted));
	}

	public void testLegacyDesDecrypt() throws Exception {
		EncryptionXmlAdapter adapter = new EncryptionXmlAdapter();
		assertEquals("${DATABASE_PASSWORD}", adapter.unmarshal("${encrypted:Z6PaU/h1ICnmR+ZTdFqxlVgkFyr/Tf65}"));
	}

	public void testPlainValueIsUnchanged() throws Exception {
		assertEquals("plain", new EncryptionXmlAdapter().unmarshal("plain"));
	}
}
