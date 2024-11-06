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
