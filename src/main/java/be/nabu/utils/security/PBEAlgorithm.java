package be.nabu.utils.security;

public enum PBEAlgorithm {
	DES("PBEWithMD5AndDES"),
	AES128("PBEWithHmacSHA256AndAES_128"),
	AES256("PBEWithHmacSHA256AndAES_256")
	;
	
	private String name;

	private PBEAlgorithm(String name) {
		this.name = name;
	}
	
	public String getAlgorithm() {
		return name;
	}
}
