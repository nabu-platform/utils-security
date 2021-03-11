package be.nabu.utils.security.api;

import java.security.cert.X509Certificate;

public interface UntrustedHandler {
	public void handle(X509Certificate[] chain, boolean client, String authType);
}
