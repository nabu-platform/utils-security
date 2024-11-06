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
import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.util.encoders.Base32;
import org.bouncycastle.util.encoders.Hex;

// inspired by taimos implementation and some articles
public class TOTP {
	
	public static void main(String...args) {
		String key = generateKey();
		System.out.println("key: " + key);
		for (int i = 0; i < 100; i++) {
			System.out.println("otp: " + getOtp(key));
			try {
				Thread.sleep(20000);
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}
	
	public static String generateKey() {
		SecureRandom random = new SecureRandom();
		byte[] bytes = new byte[20];
		random.nextBytes(bytes);
		return Base32.toBase32String(bytes);
	}
	
	private static long getStep() {
		// 30s (id totp)
		return System.currentTimeMillis() / 30000;
	}
	
	public static String getOtp(String secret) {
		// convert the "normal" secret to hex
	    byte[] bytes = Base32.decode(secret);
	    secret = Hex.toHexString(bytes);
		
		long step = getStep();
		// format as hex (the x, for decimal use d) with leading 0 up to 16
		String steps = String.format("%016x", step).toUpperCase();
		
		byte[] message = hexToBytes(steps);
		byte[] key = hexToBytes(secret);
		try {
			byte[] hash = SecurityUtils.mac(key, new ByteArrayInputStream(message), MacAlgorithm.HmacSHA1);
			int offset = hash[hash.length - 1] & 0xf;
			int binary = ((hash[offset] & 0x7f) << 24) | ((hash[offset + 1] & 0xff) << 16) | ((hash[offset + 2] & 0xff) << 8) | (hash[offset + 3] & 0xff);
			int otp = binary % 1000000;
			return String.format("%06d", otp);
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	private static byte[] hexToBytes(final String hex) {
		// Adding one byte to get the right conversion
		// values starting with "0" can be converted
		final byte[] bArray = new BigInteger("10" + hex, 16).toByteArray();
		final byte[] ret = new byte[bArray.length - 1];
		// Copy all the REAL bytes, not the "first"
		System.arraycopy(bArray, 1, ret, 0, ret.length);
		return ret;
	}
}
