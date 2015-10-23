package be.nabu.utils.security;

public enum DigestAlgorithm {
	SHA1("1.3.14.3.2.26", "SHA-1"),
	MD5("1.2.840.113549.2.5", "MD5"),
	SHA256("2.16.840.1.101.3.4.2.1", "SHA-256"),
	SHA384("2.16.840.1.101.3.4.2.2", "SHA-384"),
	SHA512("2.16.840.1.101.3.4.2.3", "SHA-512"),
	SHA224("2.16.840.1.101.3.4.2.4", "SHA-224"),
	GOST3411("1.2.643.2.2.9", "GOST-3411"),
	RIPEMD160("1.3.36.3.2.1", "RIPEMD-160"),
	RIPEMD128("1.3.36.3.2.2", "RIPEMD-128"),
	RIPEMD256("1.3.36.3.2.3", "RIPEMD-256")
	;
	
	private String oid;
	private String name;
	
	private DigestAlgorithm(String oid, String name) {
		this.oid = oid;
		this.name = name;
	}
	
	public String getOID() {
		return oid;
	}

	public String getName() {
		return name;
	}
	
}
