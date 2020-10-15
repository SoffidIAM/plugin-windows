import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Iterator;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAuthHandler;
import com.novell.ldap.LDAPAuthProvider;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPControl;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPJSSESecureSocketFactory;
import com.novell.ldap.LDAPReferralException;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.LDAPSearchResults;
import com.novell.ldap.controls.LDAPPagedResultsControl;
import com.novell.ldap.controls.LDAPPagedResultsResponse;

public class DomainTest {
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
		LDAPPagedResultsControl pageResult = new LDAPPagedResultsControl(
				c.getSearchConstraints().getMaxResults(),
				false);

//		LDAPConstraints constraints = new LDAPConstraints();
//		constraints.setControls( 
//				new LDAPControl [] {
//					new LDAPControl ("1.2.840.113556.1.4.528", true, null),
//					pageResult
//				});
//		constraints.setReferralHandler(rh);
//		c.setConstraints(constraints);
		

		LDAPSearchConstraints ldsc = new LDAPSearchConstraints();
		ldsc.setReferralFollowing(true);
		ldsc.setReferralHandler(rh);
		ldsc.setDereference(ldsc.DEREF_NEVER);
		ldsc.setHopLimit(10);
		ldsc.setMaxResults(c.getSearchConstraints().getMaxResults());
		ldsc.setControls( 
				new LDAPControl [] {
					new LDAPControl ("1.2.840.113556.1.4.528", true, null),
					pageResult
				});
		
		LDAPSearchResults query = c.search("dc=adsoffid,dc=lab", LDAPConnection.SCOPE_SUB, "(objectClass=*)", null,
				false, ldsc);
		do
		{
			while (query.hasMore()) {
				try {
					LDAPEntry entry = query.next();
					System.out
							.println(" =================================================================================");
	
					String dn = entry.getDN();
					System.out.println(dn);
					for (Iterator iterator = entry.getAttributeSet().iterator(); iterator.hasNext();) {
						LDAPAttribute att = (LDAPAttribute) iterator.next();
						System.out.println("  "+att.getName()+": "+att.getStringValue());
					}
				} catch (LDAPReferralException e) {
					System.out.println(e);
					System.out.println("FR:" + e.getFailedReferral());
				}
			}
			LDAPControl responseControls[] = query.getResponseControls();
			pageResult.setCookie(null); // in case no cookie is
										// returned we need
										// to step out of
										// do..while

			if (responseControls != null) {
				for (int i = 0; i < responseControls.length; i++) {
					if (responseControls[i] instanceof LDAPPagedResultsResponse) {
						LDAPPagedResultsResponse response = (LDAPPagedResultsResponse) responseControls[i];
						pageResult.setCookie(response
								.getCookie());
					}
				}
			}
		} while (pageResult.getCookie() != null);
	}
}