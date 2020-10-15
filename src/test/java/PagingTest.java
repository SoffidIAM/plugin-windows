import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAuthHandler;
import com.novell.ldap.LDAPAuthProvider;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPControl;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPJSSESecureSocketFactory;
import com.novell.ldap.LDAPReferralException;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.LDAPSearchResults;
import com.novell.ldap.controls.LDAPPagedResultsControl;
import com.novell.ldap.controls.LDAPPagedResultsResponse;

import es.caib.seycon.ng.config.Config;

public class PagingTest {
	public static void main(String args[]) throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLS"); //$NON-NLS-1$

        ctx.init(new KeyManager[0], new TrustManager[] { new AlwaysTrustManager4() }, null);
        LDAPJSSESecureSocketFactory ldapSecureSocketFactory = new LDAPJSSESecureSocketFactory (ctx.getSocketFactory());
		
		LDAPConnection c = new LDAPConnection(ldapSecureSocketFactory);

		iterate(c, 200);
		iterate(c, 400);
		iterate(c, 600);
		iterate(c, 1200);
		iterate(c, 2400);
	}

	private static void iterate(LDAPConnection c, int max) throws LDAPException,
			UnsupportedEncodingException {
		LDAPConstraints constraints = c.getConstraints();
		constraints.setReferralHandler(new LDAPAuthHandler()
		{
			public LDAPAuthProvider getAuthProvider (String host, int port)
			{
				return new LDAPAuthProvider("", new byte [0]);
			}
		});

		System.out.println("Connecting...");
		// c.connect("10.129.121.3", LDAPConnection.DEFAULT_PORT);
		c.connect("localhost", 1636);
		c.bind(LDAPConnection.LDAP_V3, "CN=SSO_ADADMIN, OU=cim.sistemas,OU=produccion,OU=Aplicaciones,OU=NoOrganizacional,DC=donostia,DC=org",
				"Ss12345!".getBytes("UTF-8"));

		System.out.println("Connected");

		LDAPSearchConstraints oldConst = c.getSearchConstraints(); // Save
		// search
		// constraints
		System.out.println ("Max results = "+c.getSearchConstraints().getMaxResults());
		LDAPPagedResultsControl pageResult = new LDAPPagedResultsControl(c
				.getSearchConstraints().getMaxResults(), true);

		boolean morePages;
		int rows = 0;
		do {
			System.out.println("Fetching query results page");
			constraints.setControls(pageResult);
			constraints.setReferralFollowing(false);
			c.setConstraints(constraints);

			LDAPSearchResults searchResults = c.search("dc=donostia,dc=org",
					LDAPConnection.SCOPE_SUB, 
					"(&(objectClass=user)(!(objectClass=computer)))", null, false);

			// Process results
			while (searchResults.hasMore()) {
				boolean add = false;
				LDAPEntry entry = null;
				try {
					entry = searchResults.next();
//					System.out.println(entry.getDN());
				} catch (LDAPReferralException e) {
					e.printStackTrace();
				} catch (LDAPException e) {
					if (e.getResultCode() == LDAPException.NO_SUCH_OBJECT)
					{
						e.printStackTrace();
						// ignore
					}
					else
						throw e;
				}
				rows ++;
				if (entry != null)
				{
					LDAPAttribute lastChangeAttribute =
							entry.getAttribute("uSNChanged");
	
					if (lastChangeAttribute != null)
					{
						System.out.println ("usnchange="+lastChangeAttribute.getStringValue());
					}
				}
				if (rows >= max)
					break;

			}
			
			System.out.println ("Rows got: "+rows);

			LDAPControl responseControls[] = searchResults
					.getResponseControls();
			pageResult.setCookie(null); // in case no cookie is returned we need
			// to step out of do..while
			morePages = false;
			if (responseControls != null) {
				System.out.println("Got response control");
				for (int i = 0; i < responseControls.length; i++) {
					System.out.println(" response[" + i + "]="
							+ responseControls[i].toString());
					if (responseControls[i] instanceof LDAPPagedResultsResponse) {
						LDAPPagedResultsResponse response = (LDAPPagedResultsResponse) responseControls[i];
						System.out.println(" response[" + i + "].cookie="
								+ response.getCookie());
						if (response.getCookie() != null) {
							morePages = true;
							pageResult.setCookie(response.getCookie());
							System.out.println("LDAP results pending");
						}
					}
				}
			}
		} while (morePages && rows < max);
	}
}


class AlwaysTrustManager4 implements X509TrustManager {


	public AlwaysTrustManager4() throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException {
		super();
	}

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
     * @see javax.net.ssl.X509TrustManager#checkServerTrusted(java.security.cert.X509Certificate[],
     *      java.lang.String)
     */
    public void checkServerTrusted(X509Certificate[] arg0, String arg1)
            throws CertificateException {
    	return ;
    }

    public void checkClientTrusted(X509Certificate[] arg0, String arg1)
            throws CertificateException {
        throw new CertificateException("No allowed to use client certificates");
    }

}
