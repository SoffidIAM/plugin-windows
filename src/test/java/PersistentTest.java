import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

import com.novell.ldap.LDAPAuthHandler;
import com.novell.ldap.LDAPAuthProvider;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPJSSESecureSocketFactory;
import com.novell.ldap.LDAPReferralException;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.LDAPSearchResults;

public class PersistentTest {
	private static LDAPConnection getConnection() throws NoSuchAlgorithmException, KeyManagementException,
			KeyStoreException, CertificateException, FileNotFoundException, IOException {
		SSLContext ctx;
		ctx = SSLContext.getInstance("TLS"); //$NON-NLS-1$

		ctx.init(new KeyManager[0], new TrustManager[] { new AlwaysTrustManager3() }, null);

		LDAPJSSESecureSocketFactory ssf = new DebugLDAPSecureSocketFactory2(ctx.getSocketFactory());
		LDAPConnection c = new LDAPConnection();
		return c;
	}

	public static void main(String args[]) throws Exception {
		LDAPConnection c = getConnection();

		System.out.println("Connecting...");
		c.connect("adserver.adsoffid.lab", LDAPConnection.DEFAULT_PORT);
		final String user = "cn=Administrator,cn=Users,dc=adsoffid,dc=lab";
		final byte[] password = "Soffid5.".getBytes("UTF-8");
		c.bind(LDAPConnection.LDAP_V3, user, password);
		

		LDAPAuthHandler rh = new LDAPAuthHandler() {
			public LDAPAuthProvider getAuthProvider(String host, int port) {
				System.out.println("Sending authentication credentials " + user + " to " + host);
				return new LDAPAuthProvider(user, password);
			}
		};
		LDAPConstraints constraints = new LDAPConstraints();
		constraints.setReferralHandler(rh);
		c.setConstraints(constraints);
		
		LDAPSearchConstraints ldsc = new LDAPSearchConstraints();
		ldsc.setReferralFollowing(true);
		ldsc.setReferralHandler(rh);
		ldsc.setDereference(ldsc.DEREF_ALWAYS);
		ldsc.setHopLimit(10);
		LDAPSearchResults query = c.search("dc=adsoffid,dc=lab", LDAPConnection.SCOPE_SUB, "(objectClass=domain)", null,
				false, ldsc);
		while (query.hasMore()) {
			try {
				LDAPEntry entry = query.next();
				System.out
						.println(" =================================================================================");

				String dn = entry.getDN();
				System.out.println();
				System.out.println();
				System.out.println("******>          Found domain " + dn);
				System.out.println();
				System.out.println();
			} catch (LDAPReferralException e) {
				System.out.println(e);
				System.out.println("FR:" + e.getFailedReferral());
			}
		}
	}
}

