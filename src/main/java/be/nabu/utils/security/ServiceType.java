package be.nabu.utils.security;

//Signature, MessageDigest, Cipher, Mac, KeyStore). 
public enum ServiceType {
	SIGNATURE("Signature"),
	MESSAGE_DIGEST("MessageDigest"),
	CIPHER("Cipher"),
	MAC("Mac"),
	KEY_PAIR_FACTORY("KeyFactory"),
	KEY_STORE("KeyStore");
	
	private String name;
	
	private ServiceType(String name) {
		this.name = name;
	}
	
	public String getName() {
		return name;
	}
}
