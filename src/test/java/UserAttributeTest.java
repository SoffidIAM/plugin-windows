import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.Map;

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
import com.soffid.iam.sync.agent.AttributesEncoder;

public class UserAttributeTest {
	public static void main(String args[]) throws Exception {
		LDAPConnection c = getConnection();

		System.out.println("Connecting...");
		c.connect("ad.bubu.lab", LDAPConnection.DEFAULT_SSL_PORT);
		c.bind(LDAPConnection.LDAP_V3, "ad\\administrator", "Test70.".getBytes("UTF-8"));

		System.out.println("Connected");

		LDAPEntry e = c.read("CN=Test User - 0001,OU=PIGS,DC=ad,DC=bubu,DC=lab");
		LDAPAttributeSet atts = e.getAttributeSet();
		byte[][] x = null;
		for (Iterator<LDAPAttribute> it = atts.iterator(); it.hasNext();) {
			LDAPAttribute att = it.next();
			if (att.getName().equals("userParameters"))
			{
				x = att.getByteValueArray();;
				System.out.println(att.getName() + "=" + Base64.encode(att.getByteValue()) + " ("
						+ att.getByteValue().length + " bytes)");
				AttributesEncoder encoder = new AttributesEncoder(x[0]);
				Map<String, String> m = encoder.parse();
				for ( String tag: m.keySet())
				{
					System.out.println(">> "+tag+" = "+m.get(tag));
				}
				encoder.put("Test", "Testículo");
				System.out.println("--------------------------");
				System.out.println(Base64.encode( encoder.getBytes()));
				m = encoder.parse();
				for ( String tag: m.keySet())
				{
					System.out.println(">> "+tag+" = "+m.get(tag));
				}
			} 
		}
	}

	private static LDAPConnection getConnection() throws NoSuchAlgorithmException, KeyManagementException,
			KeyStoreException, CertificateException, FileNotFoundException, IOException {
		SSLContext ctx;
		ctx = SSLContext.getInstance("TLS"); //$NON-NLS-1$

		ctx.init(new KeyManager[0], new TrustManager[] { new AlwaysTrustManager5() }, null);

		LDAPJSSESecureSocketFactory ssf = new LDAPJSSESecureSocketFactory(ctx.getSocketFactory());
		LDAPConnection c = new LDAPConnection(ssf);
		return c;
	}

}

class AlwaysTrustManager5 implements X509TrustManager {

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

	public AlwaysTrustManager5() throws KeyStoreException, NoSuchAlgorithmException, CertificateException,
			FileNotFoundException, IOException {
	}

}
