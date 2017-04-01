package be.nabu.utils.security;

public enum StoreType {
	JKS("JKS", null, "application/x-java-keystore"),
	PKCS12("PKCS12", "BC", "application/x-pkcs12"),
	JCEKS("JCEKS", null, "application/x-java-jceks");
	
	private String alias, provider, contentType;
	
	private StoreType(String alias, String provider, String contentType) {
		this.alias = alias;
		this.provider = provider;
		this.contentType = contentType;
	}
	public String getAlias() {
		return alias;
	}
	public String getProvider() {
		return provider;
	}
	public String getContentType() {
		return contentType;
	}
	public static StoreType findByContentType(String contentType) {
		for (StoreType type : values()) {
			if (type.getContentType().equalsIgnoreCase(contentType))
				return type;
		}
		return null;
	}
}