import java.io.FileNotFoundException;
import java.io.IOException;
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
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPJSSESecureSocketFactory;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchResults;
import com.novell.ldap.util.Base64;


public class ConsumFix {
	public static void main (String args[]) throws Exception
	{
        SSLContext ctx;
        ctx = SSLContext.getInstance("TLS"); //$NON-NLS-1$

        ctx.init(new KeyManager[0], new TrustManager[] { new AlwaysTrustManager2() }, null);

        LDAPJSSESecureSocketFactory ssf = new LDAPJSSESecureSocketFactory(ctx.getSocketFactory());
//		LDAPConnection c = new LDAPConnection(ssf);
		LDAPConnection c = new LDAPConnection();
		
		System.out.println ("Connecting...");
		c.connect("localhost", 1389);
		c.bind(LDAPConnection.LDAP_V3, "CN=Cuenta Proceso Sistema 908tmpsoffid,OU=Basica,DC=consum,DC=red",  
				"Sombr3r1to".getBytes("UTF-8"));
		

		System.out.println ("Connected");
		String queryString =
				"(&(objectClass=group)(mailNickname=*)(displayname=*))";
		 LDAPSearchResults q = c.search("dc=consum, dc=red", LDAPConnection.SCOPE_SUB, queryString,
				null, false);
		while (q.hasMore())
		{
			LDAPEntry entry = q.next();
			LDAPAttribute a = entry.getAttribute("mailNickname");
			LDAPAttribute x = entry.getAttribute("displayname");
			System.out.println(entry.getDN()+": "+a.getStringValue());
			System.out.println(" >> "+x.getStringValue());
			LDAPModification m = new LDAPModification(LDAPModification.REPLACE, 
					new LDAPAttribute("displayname", a.getStringValue()));
			c.modify(entry.getDN(), m);
//			return;
		}
	}
		
}

class AlwaysTrustManager2 implements X509TrustManager {

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
     * @see javax.net.ssl.X509TrustManager#checkServerTrusted(java.security.cert.X509Certificate[],
     *      java.lang.String)
     */
    public void checkServerTrusted(X509Certificate[] arg0, String arg1)
            throws CertificateException {
    }

    public void checkClientTrusted(X509Certificate[] arg0, String arg1)
            throws CertificateException {
        throw new CertificateException("No allowed to use client certificates");
    }

    public AlwaysTrustManager2() throws KeyStoreException,
            NoSuchAlgorithmException, CertificateException,
            FileNotFoundException, IOException {
    }


}
