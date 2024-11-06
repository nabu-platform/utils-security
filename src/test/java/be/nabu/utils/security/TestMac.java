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
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import junit.framework.TestCase;

public class TestMac extends TestCase {
	public void testMac() throws InvalidKeyException, NoSuchAlgorithmException, IllegalStateException, IOException {
		String encodeMac = SecurityUtils.encodeMac("key".getBytes(Charset.forName("UTF-8")), 
			new ByteArrayInputStream("The quick brown fox jumps over the lazy dog".getBytes(Charset.forName("UTF-8"))), 
			"HmacSHA256");
		assertEquals("f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8", encodeMac);
	}
}
