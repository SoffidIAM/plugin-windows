import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Iterator;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.bouncycastle.util.encoders.Hex;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPAuthHandler;
import com.novell.ldap.LDAPAuthProvider;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPJSSESecureSocketFactory;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPReferralException;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.LDAPSearchResults;
import com.novell.ldap.util.Base64;

public class SidTest {
	public static void main(String args[]) throws Exception {
		LDAPConnection c = getConnection();

		System.out.println("Connecting...");
		c.connect("adserver.adsoffid.lab", LDAPConnection.DEFAULT_SSL_PORT);
		c.bind(LDAPConnection.LDAP_V3, "cn=Administrator,cn=Users,dc=adsoffid,dc=lab", "Soffid5.".getBytes("UTF-8"));

		System.out.println("Connected");

		LDAPEntry e = c.read("CN=bubusito2,CN=Users,DC=adsoffid,DC=lab");
		LDAPAttributeSet atts = e.getAttributeSet();
		byte x[] = null;
		for (Iterator<LDAPAttribute> it = atts.iterator(); it.hasNext();) {
			LDAPAttribute att = it.next();
			if (att.getName().equals("objectSid"))
				x = att.getByteValue();
			if (att.getName().equals("objectSid") || att.getName().equals("objectGUID")) {
				System.out.println(att.getName() + "=" + Base64.encode(att.getByteValue()) + " ("
						+ att.getByteValue().length + " bytes)");
			} else
				System.out.println(att.getName() + "=" + att.getStringValue());
		}

		// e = new LDAPEntry("cn=bubusito2,CN=Users,DC=adsoffid,DC=lab");
		// e.getAttributeSet().add(new LDAPAttribute("sAMAccountName",
		// "bubusito2"));
		// e.getAttributeSet().add(new LDAPAttribute("objectClass", "user"));

		// S-1-5-21-225526297-2442968996-76853013-2055
		// 0501 0000 0000 0005 0015 0000 4219 0d71 bfa4 919c af15 0494 0807 0000
		byte[] b = new byte[] { 1, 5, 0, 0, 0, 0, 5, 0, 0x15, 0, 0, 0, 0x19, 0x42, 0x71, 0x0d, (byte) 0xa4, (byte) 0xbf,
				(byte) 0x9c, (byte) 0x91, 0x15, (byte) 0xaf, (byte) 0x94, 0x04, 0x07, 0x08, 0, 0 };

		LDAPModification mod = new LDAPModification(LDAPModification.ADD, new LDAPAttribute("sIDHistory", b));
		c.modify(e.getDN(), mod);
	}

	private static LDAPConnection getConnection() throws NoSuchAlgorithmException, KeyManagementException,
			KeyStoreException, CertificateException, FileNotFoundException, IOException {
		SSLContext ctx;
		ctx = SSLContext.getInstance("TLS"); //$NON-NLS-1$

		ctx.init(new KeyManager[0], new TrustManager[] { new AlwaysTrustManager() }, null);

		LDAPJSSESecureSocketFactory ssf = new LDAPJSSESecureSocketFactory(ctx.getSocketFactory());
		LDAPConnection c = new LDAPConnection(ssf);
		return c;
	}

}

class AlwaysTrustManager implements X509TrustManager {

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

	public AlwaysTrustManager() throws KeyStoreException, NoSuchAlgorithmException, CertificateException,
			FileNotFoundException, IOException {
	}

}
