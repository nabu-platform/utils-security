package be.nabu.utils.security;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;

public class SimpleHostnameVerifier implements HostnameVerifier {

	private String regex;
	
	public SimpleHostnameVerifier(String regex) {
		this.regex = regex;
	}
	
	@Override
	public boolean verify(String arg0, SSLSession arg1) {
		return arg0.matches(regex);
	}

}
