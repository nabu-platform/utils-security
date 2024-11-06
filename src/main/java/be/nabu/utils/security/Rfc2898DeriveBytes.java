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
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.util.Arrays;

import be.nabu.utils.codec.TranscoderUtils;
import be.nabu.utils.codec.impl.Base64Decoder;
import be.nabu.utils.codec.impl.Base64Encoder;
import be.nabu.utils.io.IOUtils;

/**
 * RFC 2898 password derivation compatible with .NET Rfc2898DeriveBytes class
 * .NET:
 * https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.rfc2898derivebytes?view=net-7.0
 * 
 * Sources: -
 * https://stackoverflow.com/questions/24405731/rfc2898derivebytes-in-java -
 * https://github.com/blabla1337/skf-workshop-java/blob/master/src/main/resources/com/Lib/Rfc2898DeriveBytes.java
 * - https://www.medo64.com/2010/05/java-rfc2898derivebytes/ -
 * https://www.example-code.com/java/pbkdf2_duplicate_Rfc2898DeriveBytes.asp
 */
public class Rfc2898DeriveBytes {

	private Mac hmac;
	private byte[] salt;
	private int iterations;

	private byte[] buffer = new byte[20];
	private int bufferStartIndex = 0;
	private int bufferEndIndex = 0;
	private int block = 1;

	/**
	 * Creates new instance.
	 * 
	 * @param password   The password used to derive the key.
	 * @param salt       The key salt used to derive the key.
	 * @param iterations The number of iterations for the operation.
	 * @throws NoSuchAlgorithmException HmacSHA1 algorithm cannot be found.
	 * @throws InvalidKeyException      Salt must be 8 bytes or more. -or- Password
	 *                                  cannot be null.
	 */
	public Rfc2898DeriveBytes(byte[] password, byte[] salt, int iterations) throws InvalidKeyException, NoSuchAlgorithmException {
		if (salt.length < 8) {
			throw new IllegalArgumentException("Salt should be at least 8 bytes long");
		}
		this.salt = salt;
		this.iterations = iterations;
		this.hmac = Mac.getInstance("HmacSHA1");
		this.hmac.init(new SecretKeySpec(password, "HmacSHA1"));
	}

	public Rfc2898DeriveBytes(byte[] password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeyException {
		this(password, salt, 1000);
	}

	public static String generateCryptoHash(String passwordToHash) throws InvalidKeyException, NoSuchAlgorithmException, IOException {
		byte[] salt = new byte[16];
		// generate a secure salt
		new SecureRandom().nextBytes(salt);
		Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(passwordToHash.getBytes("UTF-8"), salt, 1000);
		byte[] hashed = rfc2898DeriveBytes.getBytes(32);
		byte[] result = new byte[49];
		System.arraycopy(salt, 0, result, 1, salt.length);
		System.arraycopy(hashed, 0, result, 1 + salt.length, hashed.length);
		byte[] encoded = IOUtils.toBytes(TranscoderUtils.transcodeBytes(
			IOUtils.wrap(result, true), 
			new Base64Encoder())
		);
		return new String(encoded, "UTF-8");
	}
	
	// the Microsoft.AspNet.Identity.Crypto class uses the Rfc2898 class in a
	// specific way
	// we want to be able to validate hashes generated this way
	public static boolean validateCryptoHash(String hash, String passwordToCheck) throws InvalidKeyException, NoSuchAlgorithmException, IOException {
		byte[] decoded = IOUtils.toBytes(TranscoderUtils.transcodeBytes(
			IOUtils.wrap(hash.getBytes("UTF-8"), true), 
			new Base64Decoder())
		);
		byte[] salt = new byte[16];
		byte[] result = new byte[32];
		// starts of at 1 for some reason...
		System.arraycopy(decoded, 1, salt, 0, salt.length);
		System.arraycopy(decoded, 1 + salt.length, result, 0, result.length);

		Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(passwordToCheck.getBytes("UTF-8"), salt, 1000);
		byte[] bytes = rfc2898DeriveBytes.getBytes(32);
		return Arrays.areEqual(bytes, result);
	}

	/**
	 * Returns a pseudo-random key from a password, salt and iteration count.
	 * @param count Number of bytes to return.
	 */
	public byte[] getBytes(int count) {
		byte[] result = new byte[count];
		int resultOffset = 0;
		int bufferCount = this.bufferEndIndex - this.bufferStartIndex;

		// if there is some data in buffer
		if (bufferCount > 0) {
			if (count < bufferCount) { // if there is enough data in buffer
				System.arraycopy(this.buffer, this.bufferStartIndex, result, 0, count);
				this.bufferStartIndex += count;
				return result;
			}
			System.arraycopy(this.buffer, this.bufferStartIndex, result, 0, bufferCount);
			this.bufferStartIndex = this.bufferEndIndex = 0;
			resultOffset += bufferCount;
		}

		while (resultOffset < count) {
			int needCount = count - resultOffset;
			this.buffer = this.secretSauce();
			if (needCount > 20) { // we one (or more) additional passes
				System.arraycopy(this.buffer, 0, result, resultOffset, 20);
				resultOffset += 20;
			}
			else {
				System.arraycopy(this.buffer, 0, result, resultOffset, needCount);
				this.bufferStartIndex = needCount;
				this.bufferEndIndex = 20;
				return result;
			}
		}
		return result;
	}

	private byte[] secretSauce() {
		this.hmac.update(this.salt, 0, this.salt.length);
		byte[] tempHash = this.hmac.doFinal(getBytesFromInt(this.block));

		this.hmac.reset();
		byte[] finalHash = tempHash;
		for (int i = 2; i <= this.iterations; i++) {
			tempHash = this.hmac.doFinal(tempHash);
			for (int j = 0; j < 20; j++) {
				finalHash[j] = (byte) (finalHash[j] ^ tempHash[j]);
			}
		}
		// because it is unsigned in c#
		if (this.block == 2147483647) {
			this.block = -2147483648;
		}
		else {
			this.block += 1;
		}

		return finalHash;
	}

	private static byte[] getBytesFromInt(int i) {
		return new byte[] { (byte) (i >>> 24), (byte) (i >>> 16), (byte) (i >>> 8), (byte) i };
	}

}