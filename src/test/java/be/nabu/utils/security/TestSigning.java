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
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import be.nabu.utils.io.api.ByteBuffer;
import be.nabu.utils.io.api.Container;
import junit.framework.TestCase;
import static be.nabu.utils.io.IOUtils.*;

public class TestSigning extends TestCase {
	
	public void testSelfSign() throws GeneralSecurityException, IOException {
		KeyPair pair = SecurityUtils.generateKeyPair(KeyPairType.RSA, 1024);
		X500Principal issuer = SecurityUtils.createX500Principal("test", null, null, null, "Antwerp", "Belgium");
		X509Certificate certificate = BCSecurityUtils.generateSelfSignedCertificate(pair, yearLong(), issuer, issuer);
		
		String data = "MIME-Version: 1.0\r\nContent-Type: text/plain;\r\n\r\nthis is a test";
		Container<ByteBuffer> container = newByteBuffer();
		container = wrap(
			container,
			wrap(BCSecurityUtils.sign(toOutputStream(container), BCSecurityUtils.createSignerStore(
				BCSecurityUtils.createSigner(pair.getPrivate(), certificate, SignatureType.SHA1WITHRSA)
			), false))
		);
		container.write(wrap(data.getBytes("ASCII"), true));
		container.close();
		
		// this contains the signature(s) of the data
		byte [] signatures = toBytes(container);
		
		assertNotNull(BCSecurityUtils.verify(
				new ByteArrayInputStream(data.getBytes("ASCII")), 
				signatures, 
				BCSecurityUtils.createCertificateStore(new X509Certificate[] { certificate }), 
				certificate));
	}
	
	public void testSign() throws IOException, GeneralSecurityException {
		X500Principal issuer = SecurityUtils.createX500Principal("testCA", null, null, null, "Antwerp", "Belgium");
		// ca
		KeyPair caPair = SecurityUtils.generateKeyPair(KeyPairType.RSA, 1024);
		X509Certificate ca = BCSecurityUtils.generateSelfSignedCertificate(caPair, yearLong(), issuer, issuer);
		// user
		X500Principal subject = SecurityUtils.createX500Principal("testUser", null, null, null, "Antwerp", "Belgium");
		KeyPair userPair = SecurityUtils.generateKeyPair(KeyPairType.RSA, 1024);
		byte [] csr = BCSecurityUtils.generatePKCS10(userPair, SignatureType.SHA1WITHRSA, subject);
		// sign user with ca
		X509Certificate user = BCSecurityUtils.signPKCS10(csr, yearLong(), issuer, caPair.getPrivate());
		
		String data = "this is my data that serves as a test of signature generation and verification";
		Container<ByteBuffer> container = newByteBuffer();
		
		container = wrap(
			container,
			wrap(BCSecurityUtils.sign(toOutputStream(container), BCSecurityUtils.createSignerStore(
				BCSecurityUtils.createSigner(userPair.getPrivate(), user, SignatureType.SHA1WITHRSA)
			), false))
		);
		container.write(wrap(data.getBytes("ASCII"), true));
		container.close();
		
		// this contains the signature(s) of the data
		byte [] signatures = toBytes(container);
		
		assertNotNull(BCSecurityUtils.verify(
				new ByteArrayInputStream(data.getBytes("ASCII")), 
				signatures, 
				BCSecurityUtils.createCertificateStore(new X509Certificate[] { user }), 
				ca));
	}
	
	public void testEnclosedSelfSigned() throws GeneralSecurityException, IOException {
		KeyPair pair = SecurityUtils.generateKeyPair(KeyPairType.RSA, 1024);
		X500Principal issuer = SecurityUtils.createX500Principal("test", null, null, null, "Antwerp", "Belgium");
		X509Certificate certificate = BCSecurityUtils.generateSelfSignedCertificate(pair, yearLong(), issuer, issuer);
		
		String data = "MIME-Version: 1.0\r\nContent-Type: text/plain;\r\n\r\nthis is a test";
		Container<ByteBuffer> container = newByteBuffer();
		container = wrap(
			container,
			wrap(BCSecurityUtils.sign(toOutputStream(container), BCSecurityUtils.createSignerStore(
				BCSecurityUtils.createSigner(pair.getPrivate(), certificate, SignatureType.SHA1WITHRSA)
			), true))
		);
		container.write(wrap(data.getBytes("ASCII"), true));
		container.close();
		
		// this now contains the signed data
		byte [] signedData = toBytes(container);
		
		assertNotNull(BCSecurityUtils.verify(
				new ByteArrayInputStream(signedData), 
				BCSecurityUtils.createCertificateStore(new X509Certificate[] { certificate }), 
				certificate));
	}
	
	public static Date yearLong() {
		return new Date(new Date().getTime() + 1000*60*60*24*365);
	}

}
