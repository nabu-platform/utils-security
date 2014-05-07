package be.nabu.utils.security;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.xml.bind.annotation.adapters.XmlAdapter;

import be.nabu.utils.codec.TranscoderUtils;
import be.nabu.utils.codec.impl.Base64Decoder;
import be.nabu.utils.codec.impl.Base64Encoder;
import be.nabu.utils.io.IOUtils;

public class EncryptionXmlAdapter extends XmlAdapter<String, String> {

	public static final String ENCRYPTION_ALGO = "PBEWithMD5AndDES";
	
	public static final String CONFIGURATION_CRYPT_KEY = "be.nabu.utils.security.crypt.key";
	
	// must be 8 bytes
	private static byte[] salt = { (byte)0xc7, (byte)0x73, (byte)0x21, (byte)0x8c,
			(byte)0x7e, (byte)0xc8, (byte)0xee, (byte)0x99 };

	private static SecretKey key;

	// iteration count 20?
	private static AlgorithmParameterSpec paramSpec = new PBEParameterSpec(salt, 1024);
	
	protected static SecretKey getKey() throws InvalidKeySpecException, NoSuchAlgorithmException {
		if (key == null) {
			SecretKeyFactory factory = SecretKeyFactory.getInstance(ENCRYPTION_ALGO);
			KeySpec keySpec = new PBEKeySpec(System.getProperty(CONFIGURATION_CRYPT_KEY, "changeit").toCharArray());
			key = factory.generateSecret(keySpec);
		}
		return key;
	}
	
	protected Cipher getEncryptionCipher() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, InvalidKeySpecException {
		Cipher encryptionCipher = Cipher.getInstance(ENCRYPTION_ALGO);
		encryptionCipher.init(Cipher.ENCRYPT_MODE, getKey(), paramSpec);
		return encryptionCipher;
	}
	
	protected Cipher getDecryptionCipher() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, InvalidKeySpecException {
		Cipher decryptionCipher = Cipher.getInstance(ENCRYPTION_ALGO);
		decryptionCipher.init(Cipher.DECRYPT_MODE, getKey(), paramSpec);
		return decryptionCipher;
	}
	
	@Override
	public String marshal(String v) throws Exception {
		byte [] encrypted = getEncryptionCipher().doFinal(v.getBytes("UTF-8"));
		byte [] encoded = IOUtils.toBytes(TranscoderUtils.transcodeBytes(
			IOUtils.wrap(encrypted, true), 
			new Base64Encoder())
		);
		return "${encrypted:" + new String(encoded, "ASCII") + "}";
	}

	@Override
	public String unmarshal(String v) throws Exception {
		if (v.startsWith("${encrypted:") && v.endsWith("}")) {
			byte [] decoded = IOUtils.toBytes(TranscoderUtils.transcodeBytes(
				IOUtils.wrap(v.substring(12, v.length() - 1).getBytes("ASCII"), true), 
				new Base64Decoder())
			);
			byte [] decrypted = getDecryptionCipher().doFinal(decoded);
			return new String(decrypted, "UTF-8");
		}
		else
			return v;
	}

}
