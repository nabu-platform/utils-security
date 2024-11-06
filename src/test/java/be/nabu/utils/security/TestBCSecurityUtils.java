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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

import javax.security.auth.x500.X500Principal;

import junit.framework.TestCase;
import be.nabu.utils.io.IOUtils;
import be.nabu.utils.io.api.CharBuffer;

public class TestBCSecurityUtils extends TestCase {

	public void testPKCS10() throws NoSuchAlgorithmException, IOException {
		KeyPair pair = SecurityUtils.generateKeyPair(KeyPairType.RSA, 2048);
		X500Principal principal = SecurityUtils.createX500Principal("test", "Nabu", null, "Antwerp", "Antwerp", "BE");
		
		CharBuffer actual = IOUtils.newCharBuffer();
		BCSecurityUtils.encodePKCS10(
			new ByteArrayInputStream(BCSecurityUtils.generatePKCS10(pair, SignatureType.SHA1WITHRSA, principal)),
			IOUtils.toWriter(actual)
		);
		String content = IOUtils.toString(actual);
		// the csr is different every time so can't check the actual copy
		// can check the length though
		assertEquals(980, content.length());
		
		X500Principal subject = BCSecurityUtils.getPKCS10Subject(new StringReader(content));
		assertEquals(SecurityUtils.getParts(principal), SecurityUtils.getParts(subject));
	}
	
	
	
}
