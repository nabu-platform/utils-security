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

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import junit.framework.TestCase;

public class TestPBEEncrypt extends TestCase {

	public void testPbeDES() throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidParameterSpecException, UnsupportedEncodingException, IOException {
		String text = "test";
		String pbeEncrypt = SecurityUtils.pbeEncrypt(text.getBytes("UTF-8"), text, PBEAlgorithm.DES);
		byte[] pbeDecrypt = SecurityUtils.pbeDecrypt(pbeEncrypt, text, PBEAlgorithm.DES);
		assertEquals(text, new String(pbeDecrypt, "UTF-8"));
	}
	
	public void testPbeAES() throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidParameterSpecException, UnsupportedEncodingException, IOException {
		String text = "testing the aes version as well to see if it matches the things that i would expect";
		String pbeEncrypt = SecurityUtils.pbeEncrypt(text.getBytes("UTF-8"), "test", PBEAlgorithm.AES128);
		byte[] pbeDecrypt = SecurityUtils.pbeDecrypt(pbeEncrypt, "test", PBEAlgorithm.AES128);
		assertEquals(text, new String(pbeDecrypt, "UTF-8"));
	}
}
