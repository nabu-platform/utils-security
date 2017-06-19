package be.nabu.utils.security;

public enum SSLContextType {
	SSL("SSLv3"), TLS("TLS");
	
	private String name;

	private SSLContextType(String name) {
		this.name = name;
	}

	public String getName() {
		return name;
	}
}
