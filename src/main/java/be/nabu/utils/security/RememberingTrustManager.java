package be.nabu.utils.security;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.X509TrustManager;

import be.nabu.utils.security.api.UntrustedHandler;

public class RememberingTrustManager implements X509TrustManager {

	private X509TrustManager parent;
	private X509Certificate[] lastClient, lastServer;
	private UntrustedHandler handler;

	public RememberingTrustManager(X509TrustManager parent) {
		this(parent, null);
	}
	
	public RememberingTrustManager(X509TrustManager parent, UntrustedHandler handler) {
		this.parent = parent;
		this.handler = handler;
	}
	
	@Override
	public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
		lastClient = chain;
		try {
			parent.checkClientTrusted(chain, authType);
		}
		catch (CertificateException e) {
			if (handler != null) {
				handler.handle(chain, true, authType);
			}
			throw e;
		}
	}

	@Override
	public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
		lastServer = chain;
		try {
			parent.checkServerTrusted(chain, authType);
		}
		catch (CertificateException e) {
			if (handler != null) {
				handler.handle(chain, false, authType);
			}
			throw e;
		}
	}

	@Override
	public X509Certificate[] getAcceptedIssuers() {
		return parent.getAcceptedIssuers();
	}

	public UntrustedHandler getHandler() {
		return handler;
	}
	public void setHandler(UntrustedHandler handler) {
		this.handler = handler;
	}

	public X509Certificate[] getLastClient() {
		return lastClient;
	}

	public X509Certificate[] getLastServer() {
		return lastServer;
	}

	public X509TrustManager getParent() {
		return parent;
	}

}
