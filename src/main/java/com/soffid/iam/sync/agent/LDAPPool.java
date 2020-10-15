package com.soffid.iam.sync.agent;

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
import java.util.LinkedList;
import java.util.List;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.xml.security.stax.ext.InboundSecurityContext;
import org.slf4j.Logger;

import com.novell.ldap.LDAPAuthHandler;
import com.novell.ldap.LDAPAuthProvider;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPJSSESecureSocketFactory;
import com.novell.ldap.LDAPSocketFactory;

import es.caib.seycon.ng.comu.Password;
import es.caib.seycon.ng.config.Config;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.sync.engine.pool.AbstractPool;

public class LDAPPool extends AbstractPool<LDAPConnection> {

	String loginDN;
	Password password;
	private String ldapHost;
	private int ldapPort;
	private int ldapVersion;
	private String baseDN;
	private String ldapHosts[];
	private boolean alwaysTrust;
	private boolean followReferrals = true;
	private boolean debug = false;
	private List<LDAPPool> childPools = new LinkedList<LDAPPool>();
	
	public boolean isUseSsl() {
		return useSsl;
	}

	public void setUseSsl(boolean useSsl) {
		if (this.useSsl != useSsl)
		{
			this.useSsl = useSsl;
			reconfigure();
		}
			
	}

	private boolean useSsl = true;
	
	private Logger log;
	private LDAPAuthHandler ldapAuthHandler;
	private Long queryTimeout;
	
	public LDAPAuthHandler getLdapAuthHandler() {
		return ldapAuthHandler;
	}

	public void setLdapAuthHandler(LDAPAuthHandler ldapAuthHandler) {
		this.ldapAuthHandler = ldapAuthHandler;
	}

	public Logger getLog() {
		return log;
	}

	public void setLog(Logger log2) {
		this.log = log2;
	}

	public boolean isDebug() {
		return debug;
	}

	public void setDebug(boolean debug) {
		this.debug = debug;
	}

	public String getLdapHost() {
		return ldapHost;
	}

	public void setLdapHost(String ldapHost) {
		if (this.ldapHost == null || ! this.ldapHost.equals(ldapHost))
		{
			this.ldapHost = ldapHost;
			ldapHosts = ldapHost.split("[, ]+");
			reconfigure();
		}
	}

	public int getLdapPort() {
		return ldapPort;
	}

	public void setLdapPort(int ldapPort) {
		if (this.ldapPort  != ldapPort)
		{
			this.ldapPort = ldapPort;
			reconfigure();
		}
	}

	public int getLdapVersion() {
		return ldapVersion;
	}

	public void setLdapVersion(int ldapVersion) {
		if (this.ldapVersion  != ldapVersion)
		{
			this.ldapVersion = ldapVersion;
			reconfigure();
		}
	}

	public String getBaseDN() {
		return baseDN;
	}

	public void setBaseDN(String baseDN) {
		if (this.baseDN == null || ! this.baseDN.equals(baseDN))
		{
			this.baseDN = baseDN;
			reconfigure();
		}
	}

	public String getLoginDN() {
		return loginDN;
	}

	public void setLoginDN(String loginDN) {
		if (this.loginDN == null || ! this.loginDN.equals(loginDN))
		{
			this.loginDN = loginDN;
			reconfigure();
		}
	}

	public Password getPassword() {
		return password;
	}

	public void setPassword(Password password) {
		if (this.password == null || ! this.password.getPassword().equals(password.getPassword()))
		{
			this.password = password;
			reconfigure();
		}
	}

	@Override
	protected LDAPConnection createConnection() throws Exception {
		Exception lastException = null;
		for (String host: ldapHosts)
		{
//			log.info("============ Creating connection to "+host);
//			diag(log);
			try {
				return createConnection(host);
			} catch (Exception e) {
				log.info("Error connecting to LDAP server "+host+": ", e);
				lastException = e;
			}
		}
		
		if (lastException == null)
			throw new InternalErrorException ("No host configured");
		else
			throw lastException;
		
	}

	protected LDAPConnection createConnection(String host) throws Exception {
		try {
			return createConnection (host, useSsl, ldapPort);
		} catch (Exception e) {
			if (alwaysTrust && useSsl) {
				return createConnection (host, false, LDAPConnection.DEFAULT_PORT);
			}
			else
				throw e;
		}
		
	}
	
	protected LDAPConnection createConnection(String host, boolean ssl, int port) throws Exception {
		LDAPConnection conn;
		if (ssl)
		{
			
			LDAPSocketFactory ldapSecureSocketFactory = null;


			SSLContext ctx;
			if (alwaysTrust)
			{
				ctx = SSLContext.getInstance("TLS"); //$NON-NLS-1$
		        ctx.init(new KeyManager[0], new TrustManager[] { new AlwaysTrustManager() }, null);
			}
			else
			{
				ctx = SSLContext.getDefault();
			}
			
			if (debug)
			{
//				if (log != null)
//					log.debug("Creating LDAP connection to "+host);
				DebugLDAPSecureSocketFactory factory = new DebugLDAPSecureSocketFactory(ctx.getSocketFactory());
				if (log != null)
					factory.setLog(log);
				ldapSecureSocketFactory = factory;
				
			}
			else
				ldapSecureSocketFactory = new LDAPJSSESecureSocketFactory(ctx.getSocketFactory());
			
			conn = new LDAPConnection(ldapSecureSocketFactory);
		} else  {
			conn = new LDAPConnection();
			if (debug && false)
				log.warn("Created plain connection "+baseDN, new Exception());
		}
		
		try 
		{
			LDAPConstraints constraints = conn.getConstraints();
			constraints.setReferralFollowing(followReferrals);
			ldapAuthHandler = new LDAPAuthHandler()
			{
				public LDAPAuthProvider getAuthProvider (String host, int port)
				{
					if (debug && false)
						log.info("Sending authentication credentials "+
								loginDN+ ", " + baseDN+
								" to "+host);
					try
					{
						return new LDAPAuthProvider(loginDN+ ", " + baseDN, password.getPassword()
								.getBytes("UTF-8"));
					}
					catch (UnsupportedEncodingException e)
					{
						return new LDAPAuthProvider(loginDN+ ", " + baseDN, password.getPassword()
								.getBytes());
					}
				}
			};
			constraints.setReferralHandler(ldapAuthHandler);
			if (queryTimeout != null)
				constraints.setTimeLimit(queryTimeout.intValue());
			conn.setConstraints(constraints);
			conn.connect(host, port);
			conn.bind(ldapVersion, loginDN, password.getPassword()
					.getBytes("UTF8"));
			conn.setConstraints(constraints);
		}
		catch (UnsupportedEncodingException e)
		{
			throw new InternalErrorException("Error encoding UTF8:" + e.toString(),
					e);
		}
		catch (LDAPException e)
		{
			if (conn != null)
				conn.disconnect();
			throw new InternalErrorException("Failed to connect to LDAP server "+host+" with base domain "+baseDN+" : ("
					+ loginDN + ")" + e.toString(), e);
		}
		return (conn);
	}

	@Override
	protected boolean isConnectionValid(LDAPConnection connection)
			throws Exception {
		return connection.isConnected() && connection.isConnectionAlive();
	}

	@Override
	protected void closeConnection(LDAPConnection connection) throws LDAPException {
		log.warn("Closing connection "+connection.getHost(), new Exception());
		connection.disconnect();
	}

	public void setAlwaysTrust(boolean trustEveryThing) {
		if (this.alwaysTrust != trustEveryThing)
		{
			this.alwaysTrust = trustEveryThing;
			reconfigure();
		}
		
	}

	public void setFollowReferrals(boolean followReferrals) {
		if (this.followReferrals != followReferrals)
		{
			this.followReferrals = followReferrals;
			reconfigure();
		}
	}

	public List<LDAPPool> getChildPools() {
		return childPools;
	}

	public void setChildPools(List<LDAPPool> childPools) {
		this.childPools = childPools;
	}

	public void setQueryTimeout(Long timeout) {
		this.queryTimeout = timeout ;
		
	}

	public boolean isAlwaysTrust() {
		return alwaysTrust;
	}

	public boolean isFollowReferrals() {
		return followReferrals;
	}

}

class AlwaysTrustManager implements X509TrustManager {

    private KeyStore ks;
	private File cacertsConf;

	public AlwaysTrustManager() throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException {
		super();
        String configDir = Config.getConfig().getHomeDir().getAbsolutePath() + File.separatorChar
                + "conf";
        // log.info("Seycon Config directory {}", configDir ,null);
        cacertsConf = new File(configDir, "cacerts");

        ks = KeyStore.getInstance("JKS");
        ks.load(new FileInputStream (cacertsConf), "changeit".toCharArray());

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
    	try {
			if (!ks.containsAlias(arg0[0].getSubjectX500Principal().getName()))
			{
				ks.setCertificateEntry(arg0[0].getSubjectX500Principal().getName(), arg0[0]);
			    ks.store( new FileOutputStream ( cacertsConf ), "changeit".toCharArray());
			}
		} catch (KeyStoreException e) {
			throw new CertificateException ("Error validating certificate", e);
		} catch (NoSuchAlgorithmException e) {
			throw new CertificateException ("Error validating certificate", e);
		} catch (FileNotFoundException e) {
			throw new CertificateException ("Error validating certificate", e);
		} catch (IOException e) {
			throw new CertificateException ("Error validating certificate", e);
		}
    	return ;
    }

    public void checkClientTrusted(X509Certificate[] arg0, String arg1)
            throws CertificateException {
        throw new CertificateException("No allowed to use client certificates");
    }

}
