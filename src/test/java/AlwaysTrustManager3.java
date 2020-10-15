import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.X509TrustManager;

class AlwaysTrustManager3 implements X509TrustManager {

	private boolean debug;

	/*
	 * (non-Javadoc)
	 * 
	 * @see javax.net.ssl.X509TrustManager#getAcceptedIssuers()
	 */
	public X509Certificate[] getAcceptedIssuers() {
		return new X509Certificate[0];

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * javax.net.ssl.X509TrustManager#checkServerTrusted(java.security.cert.
	 * X509Certificate[], java.lang.String)
	 */
	public void checkServerTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
	}

	public void checkClientTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
		throw new CertificateException("No allowed to use client certificates");
	}

	public AlwaysTrustManager3() throws KeyStoreException, NoSuchAlgorithmException, CertificateException,
			FileNotFoundException, IOException {
	}

}