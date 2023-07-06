package com.soffid.iam.sync.agent;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.commons.logging.LogFactory;
import org.slf4j.Logger;

import com.novell.ldap.LDAPAuthHandler;
import com.novell.ldap.LDAPAuthProvider;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPJSSESecureSocketFactory;
import com.novell.ldap.LDAPReferralHandler;
import com.novell.ldap.LDAPSocketFactory;

import es.caib.seycon.ng.comu.Password;
import es.caib.seycon.ng.config.Config;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.sync.engine.pool.AbstractPool;
import es.caib.seycon.util.Base64;

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

	int current = 0;
	@Override
	protected LDAPConnection createConnection() throws Exception {
		Exception lastException = null;
		List<InetAddress> ip = new LinkedList<>();
		for (String host: ldapHosts)
		{
			for (InetAddress address: InetAddress.getAllByName(host)) {
				ip.add(address);
			}
		}
		
		for (int i = 0; i < ip.size(); i++) {
			InetAddress address = ip.get( (i + current) % ip.size());
			try {
				return createConnection(address);
			} catch (Exception e) {
				log.info("Error connecting to LDAP server "+address+": ", e);
				lastException = e;
			}
			current ++;
			if (current >= ip.size()) current = 0;
		}
		
		if (lastException == null)
			throw new InternalErrorException ("No host configured");
		else
			throw lastException;
		
	}

	protected LDAPConnection createConnection(InetAddress address) throws Exception {
		try {
			return createConnection (address, useSsl, ldapPort);
		} catch (Exception e) {
			if (alwaysTrust && useSsl) {
				LDAPConnection conn = createConnection (address, false, LDAPConnection.DEFAULT_PORT);
				log.warn("Error creating SSL connection to "+address+". Switching to NON-SSL connection", e);
				return conn;
			}
			else
				throw e;
		}
		
	}
	
	protected LDAPConnection createConnection(InetAddress address, boolean ssl, int port) throws Exception {
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
			
			conn = new SecureLDAPConnection(ldapSecureSocketFactory);
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
			if (isDebug())
				log.info("Connecting to "+address.getHostName()+" "+address.getHostAddress()+":"+port);
			conn.connect(address.getHostAddress(), port);
			conn.bind(ldapVersion, loginDN, password.getPassword()
					.getBytes("UTF8"));
			conn.setConstraints(constraints);
			if (isDebug())
				log.info("Connected to "+address+":"+port);
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
			throw new InternalErrorException("Failed to connect to LDAP server "+address+" with base domain "+baseDN+" : ("
					+ loginDN + ")", e);
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
	private static String lock = new String();
    private KeyStore ks;
	private File cacertsConf;

	public AlwaysTrustManager() throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException {
		super();
        String configDir = Config.getConfig().getHomeDir().getAbsolutePath() + File.separatorChar
                + "conf";
        // log.info("Seycon Config directory {}", configDir ,null);
        cacertsConf = new File(configDir, "cacerts");

        ks = KeyStore.getInstance("JKS");
        try {
			synchronized (lock) {
				final FileInputStream in = new FileInputStream (cacertsConf);
				ks.load(in, null);
				in.close();
			}
        } catch (Exception e) {}

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
//			LogFactory.getLog(getClass()).info("Unknown cert "+arg0[0]);
			MessageDigest d = MessageDigest.getInstance("SHA-1");
			String entryName = Base64.encodeBytes( d.digest(arg0[0].getEncoded()), Base64.DONT_BREAK_LINES );
			if (ks.containsAlias(entryName))
			{
				if (! arg0[0].equals(ks.getCertificate(entryName))) {
					ks.deleteEntry(entryName);
				}
			}
			if (! ks.containsAlias(entryName)) {
				LogFactory.getLog(getClass()).info("Registering entry "+entryName);
				ks.setCertificateEntry(entryName, arg0[0]);
				synchronized (lock) {
				    final FileOutputStream out = new FileOutputStream ( cacertsConf );
					ks.store( out, "changeit".toCharArray());
					out.close();
				}
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
