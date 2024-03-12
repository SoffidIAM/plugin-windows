package com.soffid.iam.sync.agent;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.rmi.RemoteException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivilegedAction;
import java.security.URIParameter;
import java.security.cert.CertificateException;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Map.Entry;
import java.util.Set;
import java.util.Stack;
import java.util.UUID;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.security.auth.Subject;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.bouncycastle.jcajce.provider.digest.SHA384.Digest;
import org.bouncycastle.util.encoders.Hex;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

import com.hierynomus.msdtyp.ACL;
import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.msdtyp.SecurityDescriptor;
import com.hierynomus.msdtyp.SecurityDescriptor.Control;
import com.hierynomus.msdtyp.ace.ACE;
import com.hierynomus.msdtyp.ace.AceFlags;
import com.hierynomus.msdtyp.ace.AceType;
import com.hierynomus.msdtyp.ace.AceType2;
import com.hierynomus.msdtyp.ace.AceTypes;
import com.hierynomus.mssmb2.SMB2Dialect;
import com.hierynomus.security.bc.BCSecurityProvider;
import com.hierynomus.smb.SMBBuffer;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPControl;
import com.novell.ldap.LDAPDN;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPJSSESecureSocketFactory;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPReferralException;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.LDAPSearchResults;
import com.novell.ldap.LDAPSocketFactory;
import com.novell.ldap.LDAPUrl;
import com.novell.ldap.controls.LDAPPagedResultsControl;
import com.novell.ldap.controls.LDAPPagedResultsResponse;
import com.rapid7.client.dcerpc.RPCException;
import com.rapid7.client.dcerpc.dto.SID;
import com.rapid7.client.dcerpc.mserref.SystemErrorCode;
import com.rapid7.client.dcerpc.mssamr.dto.DomainHandle;
import com.rapid7.client.dcerpc.mssamr.dto.MembershipWithName;
import com.rapid7.client.dcerpc.mssamr.dto.ServerHandle;
import com.rapid7.client.dcerpc.mssamr.dto.UserAllInformation;
import com.rapid7.client.dcerpc.mssamr.dto.UserHandle;
import com.rapid7.client.dcerpc.transport.RPCTransport;
import com.rapid7.client.dcerpc.transport.SMBTransportFactories;
import com.soffid.iam.api.AccountStatus;
import com.soffid.iam.api.Group;
import com.soffid.iam.api.PasswordValidation;
import com.soffid.iam.api.Role;
import com.soffid.iam.api.RoleGrant;
import com.soffid.iam.config.Config;
import com.soffid.iam.remote.RemoteServiceLocator;
import com.soffid.iam.service.AccountService;
import com.soffid.iam.service.ApplicationService;
import com.soffid.iam.sync.engine.kerberos.ChainConfiguration;
import com.soffid.iam.sync.engine.kerberos.KerberosManager;
import com.soffid.iam.sync.intf.AccessLogMgr;
import com.soffid.iam.sync.intf.KerberosAgent;
import com.soffid.iam.sync.nas.NASManager;
import com.soffid.msrpc.samr.SamrService;
import com.soffid.msrpc.samr.UserInfo;

import es.caib.seycon.agent.WindowsNTBDCAgent;
import es.caib.seycon.ng.comu.Account;
import es.caib.seycon.ng.comu.AttributeDirection;
import es.caib.seycon.ng.comu.AttributeMapping;
import es.caib.seycon.ng.comu.Grup;
import es.caib.seycon.ng.comu.ObjectMapping;
import es.caib.seycon.ng.comu.Password;
import es.caib.seycon.ng.comu.Rol;
import es.caib.seycon.ng.comu.RolGrant;
import es.caib.seycon.ng.comu.SoffidObjectType;
import es.caib.seycon.ng.comu.Usuari;
import es.caib.seycon.ng.exception.AccountAlreadyExistsException;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownGroupException;
import es.caib.seycon.ng.exception.UnknownRoleException;
import es.caib.seycon.ng.exception.UnknownUserException;
import es.caib.seycon.ng.sync.engine.Watchdog;
import es.caib.seycon.ng.sync.engine.extobj.AccountExtensibleObject;
import es.caib.seycon.ng.sync.engine.extobj.ExtensibleObjectFinder;
import es.caib.seycon.ng.sync.engine.extobj.GrantExtensibleObject;
import es.caib.seycon.ng.sync.engine.extobj.GroupExtensibleObject;
import es.caib.seycon.ng.sync.engine.extobj.ObjectTranslator;
import es.caib.seycon.ng.sync.engine.extobj.RoleExtensibleObject;
import es.caib.seycon.ng.sync.engine.extobj.UserExtensibleObject;
import es.caib.seycon.ng.sync.engine.extobj.ValueObjectMapper;
import es.caib.seycon.ng.sync.intf.AuthoritativeChange;
import es.caib.seycon.ng.sync.intf.AuthoritativeChangeIdentifier;
import es.caib.seycon.ng.sync.intf.AuthoritativeIdentitySource2;
import es.caib.seycon.ng.sync.intf.ExtensibleObject;
import es.caib.seycon.ng.sync.intf.ExtensibleObjectMapping;
import es.caib.seycon.ng.sync.intf.ExtensibleObjectMgr;
import es.caib.seycon.ng.sync.intf.ExtensibleObjects;
import es.caib.seycon.ng.sync.intf.GroupMgr;
import es.caib.seycon.ng.sync.intf.KerberosPrincipalInfo;
import es.caib.seycon.ng.sync.intf.LogEntry;
import es.caib.seycon.ng.sync.intf.ReconcileMgr2;
import es.caib.seycon.ng.sync.intf.RoleMgr;
import es.caib.seycon.ng.sync.intf.UserMgr;
import es.caib.seycon.util.Base64;
import es.caib.seycon.util.TimedOutException;

/**
 * Agente que gestiona los usuarios y contraseñas del LDAP Hace uso de las
 * librerias jldap de Novell
 * <P>
 * 
 * @author $Author: u88683 $
 * @version $Revision: 1.5 $
 */

public class CustomizableActiveDirectoryAgent extends WindowsNTBDCAgent
		implements ExtensibleObjectMgr, UserMgr, ReconcileMgr2, RoleMgr,
		GroupMgr, KerberosAgent, AuthoritativeIdentitySource2,
		AccessLogMgr {

	public static final String SID_EVERYONE = "S-1-1-0";

	public static final String SID_SELF = "S-1-5-10";

	public static final String PASSWORD_OBJECT = "ab721a53-1e2f-11d0-9819-00aa0040529b";

	private static final String RELATIVE_DN = "relativeBaseDn";

	private static final String BASE_DN = "baseDn";

	protected static final String USER_ACCOUNT_CONTROL = "userAccountControl";

	static HashMap<String, LDAPPool> pools = new HashMap<String, LDAPPool>();

	protected static final String SAM_ACCOUNT_NAME_ATTRIBUTE = "sAMAccountName";

	final static int ADS_UF_SCRIPT = 0x1;

	final static int ADS_UF_ACCOUNTDISABLE = 0x2;

	final static int ADS_UF_HOMEDIR_REQUIRED = 0x8;

	protected final static int ADS_UF_LOCKOUT = 0x10;

	final static int ADS_UF_PASSWD_NOTREQD = 0x20;

	final static int ADS_UF_PASSWD_CANT_CHANGE = 0x40;

	final static int ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED = 0x80;

	final static int ADS_UF_TEMP_DUPLICATE_ACCOUNT = 0x100;

	protected final static int ADS_UF_NORMAL_ACCOUNT = 0x200;

	final static int ADS_UF_INTERDOMAIN_TRUST_ACCOUNT = 0x800;

	final static int ADS_UF_WORKSTATION_TRUST_ACCOUNT = 0x1000;

	final static int ADS_UF_SERVER_TRUST_ACCOUNT = 0x2000;

	protected final static int ADS_UF_DONT_EXPIRE_PASSWD = 0x10000;

	final static int ADS_UF_MNS_LOGON_ACCOUNT = 0x20000;

	final static int ADS_UF_SMARTCARD_REQUIRED = 0x40000;

	protected final static int ADS_UF_TRUSTED_FOR_DELEGATION = 0x80000;

	final static int ADS_UF_NOT_DELEGATED = 0x100000;

	final static int ADS_UF_USE_DES_KEY_ONLY = 0x200000;

	final static int ADS_UF_DONT_REQUIRE_PREAUTH = 0x400000;

	protected final static int ADS_UF_PASSWORD_EXPIRED = 0x800000;

	final static int ADS_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 0x1000000;

	protected ValueObjectMapper vom = new ValueObjectMapper();

	protected ObjectTranslator objectTranslator = null;

	private static final long serialVersionUID = 1L;

	// constante de máximo número de miembros de un grupo (evitar timeout)
	private static final int MAX_GROUP_MEMBERS = 5000;

	/** Puerto de conexion LDAP * */
	protected int ldapPort = LDAPConnection.DEFAULT_SSL_PORT;
	/** Version del servidor LDAP */
	int ldapVersion = LDAPConnection.LDAP_V3;
	/** Usuario root de conexión LDAP */
	protected String loginDN;
	/** Password del usuario administrador cn=root,dc=caib,dc=es */
	protected Password password;
	/** HOST donde se aloja LDAP */
	protected String ldapHost;

	String usersContext;
	String rolesContext;

	// Vamos a er la hora en la que empieza y la hora en la que acaba.
	long inicio;
	long fin;
	int usuarios = 0;

	protected String passwordAttribute;

	protected String hashType;

	protected String passwordPrefix;

	protected Collection<ExtensibleObjectMapping> objectMappings;

	protected String baseDN;

	protected boolean debugEnabled;
	// --------------------------------------------------------------

	private boolean trustEverything;

	private boolean followReferrals;

	protected boolean useSsl = true;

	protected boolean multiDomain;

	protected Map<String,String> domainHost = new HashMap<String, String>();
	protected Map<String,String> shortNameToDomain = new HashMap<String, String>();
	protected Map<String,String> domainToShortName = new HashMap<String, String>();
	protected Map<String,String> dnsNameToDomain = new HashMap<String, String>();
	protected Map<String,String[]> domainControllers = new HashMap<>();
	protected String mainDomain;

	protected boolean createOUs;

	private Method oldNameGetter;

	private String samDomainName;

	private String samAccountName;

	private HashMap<String, String> extendedAttributes;

	private String excludeDomains;
	
	protected NASManager nasManager;

	private String administratorDN;

	/**
	 * Constructor
	 * 
	 * @param params
	 *            Parámetros de configuración: <li>0 = código de usuario LDAP</li>
	 *            <li>1 = contraseña de acceso LDAP</li> <li>2 = host</li> <li>3
	 *            = Nombre del attribute password</li> <li>4 = Algoritmo de hash
	 *            </li>
	 */
	public CustomizableActiveDirectoryAgent() throws RemoteException {
	}
	

	@Override
	public void init() throws InternalErrorException {
		log.info ("BEGIN Initalize Active Directory agent {}",
				getDispatcher().getCodi(), null);
		loginDN = getDispatcher().getParam2();

		password = Password.decode(getDispatcher().getParam3());
		// password = params[1];
		ldapHost = getDispatcher().getParam0();
		baseDN = getDispatcher().getParam1();

		loginDN = loginDN.toLowerCase();
		try {
			new LdapName(loginDN);
			if (! loginDN.contains(baseDN.toLowerCase()))
				loginDN = loginDN + ", " + baseDN;
		} catch (InvalidNameException e) {}
		
		multiDomain = "true".equals(getDispatcher().getParam4());
		createOUs = ! "false".equals(getDispatcher().getParam5());
		excludeDomains = getDispatcher().getParam6();
		debugEnabled = "true".equals(getDispatcher().getParam7());
		trustEverything = "true".equals(getDispatcher().getParam8());
		if ("plain".equals(getDispatcher().getParam8())) {
			useSsl = false;
			ldapPort = LDAPConnection.DEFAULT_PORT;
		}
		extendedAttributes = new HashMap<String,String>();
		if (loginDN.contains("\\")) {
			samDomainName = loginDN.substring(0, loginDN.indexOf("\\"));
			samAccountName = loginDN.substring(loginDN.indexOf("\\")+1);
		}
		byte[] data = getDispatcher().getBlobParam();
		if (data != null)
		{
			String t;
			try {
				t = new String ( data,"UTF-8");
				Map m = new HashMap();
				if (t != null)
				{
					for (String tag: t.split("&")) {
						int i = tag.indexOf("=");
						String attribute;
						String v;
						try {
							attribute = i < 0 ? tag: java.net.URLDecoder.decode(tag.substring(0, i), "UTF-8");
							v = i > 0 ? java.net.URLDecoder.decode(tag.substring(i+1), "UTF-8"): null;
							extendedAttributes.put(attribute, v);
						} catch (UnsupportedEncodingException e) {
						}
					}
				}
			} catch (UnsupportedEncodingException e1) {
			} 
		}
		followReferrals = "true".equals(getDispatcher().getParam9());
		// followReferrals = false;
		
		try {
			javaDisk = new bubu.util.javadisk();
		} catch (Throwable e) {
			// e.printStackTrace();
		}
		
		Watchdog.instance().interruptMe(getDispatcher().getTimeout());

		try {
			log.info(getCodi()+": Fetching main domain for "+baseDN);
			mainDomain = baseDN;
			mainDomain = reconfigurePool(ldapHost, baseDN);
			log.info(getCodi()+": Main domain for "+baseDN+ " is "+mainDomain);
		} catch (Exception e2) {
			throw new InternalErrorException("Error querying domain short name", e2);
		}

		SmbConfig config = SmbConfig.builder()
	            .withDialects( 
	            		SMB2Dialect.SMB_2_0_2, SMB2Dialect.SMB_2_1
	            		)
	            .withSecurityProvider(new BCSecurityProvider())
	            .build();
		smbClient = new SMBClient(config );

		try {
			oldNameGetter = Account.class.getMethod("getOldName",  new Class[0]);
		} catch (NoSuchMethodException e1) {
		} catch (SecurityException e1) {
		}
		LDAPConnection conn = null;
		try {
			conn = getConnection(mainDomain);
			if ( ! conn.isTLS())
				log.warn("Warning: Using plain LDAP sockets. The connection is not secure.");
			if (multiDomain)
			{
				searchLegacyDomains(conn, excludeDomains);
				searchDomains (conn, excludeDomains);
			}
			else
			{
				try {
					LDAPEntry entry = conn.read(baseDN);
				} catch (Exception e) {
					log.info("Unable to read object "+baseDN);
				}
				domainControllers.put(mainDomain.toLowerCase(), ldapHost.split(" +"));
			}
			searchUserSamAccountName();
			nasManager = new NASManager(samDomainName, ldapHost, samAccountName, password, domainControllers);
		} catch (Exception e) {
			handleException(e, conn);
			throw new InternalErrorException(
					"Cannot connect to active directory", e);
		} finally {
			if (isDebug())
				log.info("END");
			Watchdog.instance().dontDisturb();
			returnConnection(mainDomain);
		}
	}

	private void searchUserSamAccountName() throws Exception {
		LDAPEntry entry = null;
		if (loginDN.contains("\\") || !loginDN.contains("="))
		{
			ExtensibleObject eo = new ExtensibleObject();
			eo.setObjectType(SoffidObjectType.OBJECT_ACCOUNT.getValue());
			eo.setAttribute("objectClass", "user");
			String s = multiDomain || ! loginDN.contains("\\") ? 
					loginDN.toLowerCase() : 
					loginDN.substring(loginDN.indexOf('\\')+1).toLowerCase();
			entry = searchSamAccount(eo, s);
			if (entry == null)
			{
				log.warn("Unable to locate administrator account ("+loginDN+","+baseDN+") in LDAP server");
				samDomainName = loginDN.substring(0, loginDN.indexOf("\\"));
				samAccountName = loginDN.substring(loginDN.indexOf("\\")+1);
			}
			else
			{
				samAccountName = entry.getAttribute("sAMAccountName").getStringValue();
				samDomainName = searchNTDomainForDN(entry.getDN());
				administratorDN = entry.getDN();
			}
		}
		else {
			String dn = loginDN.toLowerCase().endsWith(baseDN.toLowerCase()) ? loginDN: loginDN+","+baseDN;
			String domain = searchDomainForDN(dn);
			LDAPConnection conn = getConnection(domain);
			try {
				entry = conn.read(dn);
				administratorDN = entry.getDN();
			} catch (LDAPReferralException e) {
				if (followReferrals)
					throw e;
			} catch (LDAPException e) {
				throw new InternalErrorException("Unable to locate administrator account ("+loginDN+","+baseDN+") in LDAP server", e);
			} finally {
				returnConnection(domain);
			}
			if (entry == null) {
			} else {
				samDomainName = searchNTDomainForDN(entry.getDN());
				samAccountName = entry.getAttribute("sAMAccountName").getStringValue();
			}
		}
	}


	protected void returnConnection(String domain) throws InternalErrorException {
		LDAPPool pool = getPool(domain);
		if (pool != null) {
			pool.returnConnection();
		}
	}


	protected LDAPConnection getConnection(String domain) throws Exception {
		LDAPPool pool = getPool(domain);
		if (pool == null && domain != null) {
			log.info("Finding pool for "+domain);
			String domain2 = searchDomainForDN(domain);
			if (domain2 == null)
				throw new InternalErrorException("Cannot resolve domain "+domain);
			domain = domain2;
			log.info("Using pool "+domain);
			pool = getPool(domain);
		}
		if (pool == null) {
			throw new InternalErrorException("Unknown LDAP pool "+domain);
		}
		try {
			LDAPConnection p = pool.getConnection();
			if (readOnly || getDispatcher().isReadOnly()) p = new ReadOnlyConnection(p);
			return p;
		} catch (Exception e) {
			if (debugEnabled)
				log.info("Error connecting to "+domain);
			throw e;
		}
	}


	protected LDAPPool getPool(String domain) throws InternalErrorException {
		LDAPPool pool = pools.get( ""+getDispatcher().getId()+"/"+domain);
		return pool;
	}

	private String reconfigurePool(String host, String dn) throws Exception {
		return reconfigurePool(host, dn, null);
	}
	
	private String reconfigurePool(String host, String dn, String shortName) throws Exception {
		log.info("RECONFIGURING POOL "+dn);

		dn = dn.trim().toLowerCase();
		LDAPPool pool = pools.get( getDispatcher().getId().toString()+"/"+dn);

		if (pool == null)
			pool = new LDAPPool();
		pool.setMaxSize(20);
		pool.setUseSsl( useSsl );
		pool.setBaseDN( dn );
		pool.setLdapHost(host);
		pool.setLdapPort(ldapPort);
		pool.setLdapVersion(ldapVersion);
		pool.setLoginDN(loginDN);
		pool.setPassword(password);
		pool.setAlwaysTrust(trustEverything);
		pool.setFollowReferrals(followReferrals);
		pool.setDebug (debugEnabled);
		pool.setLog(log);
//		pool.reconfigure();
		if (getDispatcher().getTimeout() != null)
			pool.setQueryTimeout (getDispatcher().getTimeout());
		if (pool.getChildPools() != null)
		{
			for (LDAPPool childPool: pool.getChildPools())
			{
				childPool.setUseSsl( useSsl );
				childPool.setLdapPort(ldapPort);
				childPool.setLdapVersion(ldapVersion);
				childPool.setLoginDN(loginDN);
				childPool.setPassword(password);
				childPool.setAlwaysTrust(trustEverything);
				childPool.setFollowReferrals(followReferrals);
				childPool.setDebug (debugEnabled);
				childPool.setLog(log);
				childPool.reconfigure();
			}
		}
		
		LDAPConnection conn = pool.getConnection();
		try {
			if (shortName == null) {
				log.info("Searching for short domain name for "+dn);
				
				LDAPSearchConstraints constraints = new LDAPSearchConstraints(conn.getConstraints());
				constraints.setReferralFollowing(false);
				constraints.setDereference(LDAPSearchConstraints.DEREF_NEVER);
				LDAPSearchResults query = null;
				try {
					query = conn.search("cn=configuration,"+dn,
							LDAPConnection.SCOPE_SUB, "(nETBIOSName=*)", null, false,
							constraints);
				} catch (Exception e) {
					log.info("Error connecting to "+conn.getHost()+":"+conn.getPort());
					if (mainDomain != null)
						return mainDomain;
					else
						throw e;
				}
				shortName = dn.substring(dn.indexOf("dc=")+3);
				if (shortName.contains(","))
					shortName = shortName.substring(0, shortName.indexOf(","));
				
				if ( !multiDomain && samDomainName != null)
					shortName = samDomainName;
				
				if (query != null) {
	
					while (query.hasMore()) {
						try {
							LDAPEntry entry = query.next();
							String shortName2 = entry.getAttribute("nETBIOSName").getStringValue().toLowerCase();
							String ncn = entry.getAttribute("nCName").getStringValue().toLowerCase();
							String dnsName = entry.getAttribute("dnsRoot").getStringValue().toLowerCase();
							if (ncn.equalsIgnoreCase(dn)) {
								shortName = shortName2;
								domainToShortName.put(ncn, shortName2);
								shortNameToDomain.put(shortName2, ncn);
								dnsNameToDomain.put(dnsName, ncn);
								domainControllers.put(shortName.toLowerCase(), new String[] {dnsName});
								log.info("Legacy name for "+ncn+" = "+shortName.toUpperCase());
							}
			            } catch (LDAPReferralException e)
			            {
			              // Ignore
			            } catch (LDAPException e)
			            {
			              handleException(e, conn);
			              log.info("Error getting short domain name "+e.toString());
			            }
					}
				}
				shortName = shortName.trim().toLowerCase();
			}
			if (! domainToShortName.containsKey(dn.toLowerCase()))
			{
				domainToShortName.put(dn.toLowerCase(), shortName);
				shortNameToDomain.put(shortName, dn.toLowerCase());
				String dnsName = dn.toLowerCase().replace(",dc=", ".").replace("dc=", "");
				dnsNameToDomain.put(dnsName, dn.toLowerCase());
				domainControllers.put(shortName.toLowerCase(), new String[] {dnsName});
			}
			pools.put( getDispatcher().getId().toString()+"/"+dn, pool);
			domainHost.put(dn, host);
			log.info("Registered domain "+shortName+" for "+dn+" (server "+host+")");
			return dn;
		} catch (Exception e) {
			handleException(e, conn);
			throw e;
		} finally {
			pool.returnConnection();
		}
		
	}

    private void createChildPools(LDAPPool pool2) throws InternalErrorException {
		LDAPConnection conn = null;
		LinkedList<LDAPPool> children = new LinkedList<LDAPPool>();
		String[] excluded = excludeDomains == null ? new String[0] : excludeDomains.split(" +");
		Arrays.sort(excluded);
		try {
			log.info("Resolving domain controllers for "+pool2.getLdapHost());
			
			conn = pool2.getConnection();
			LDAPSearchConstraints constraints = new LDAPSearchConstraints(conn.getConstraints());
			LDAPSearchResults query = conn.search(pool2.getBaseDN(),
						LDAPConnection.SCOPE_SUB, 
						"(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
						null, false,
						constraints);
			while (query.hasMore()) {
				try {
					LDAPEntry entry = query.next();
					LDAPAttribute dnsName = entry.getAttribute("dNSHostName");
					if (dnsName != null)
					{
						String hostName = dnsName.getStringValue();
						if (Arrays.binarySearch(excluded, hostName) >= 0)
							log.info("  IGNORING domain controller: "+hostName);
						else {
							log.info("  Found domain controller: "+hostName);
							children.add( createChildPool(pool2.getBaseDN(), hostName, pool2));
						}
					}
				} catch (LDAPReferralException e)
				{
				}
			}			

		} catch (UnknownHostException e) {
			log.warn("Error resolving host "+pool2.getLdapHost(), e);
		} catch (LDAPException e1) {
			handleException(e1, conn);
			log.warn("Error querying domain controllers ", e1);
		} catch (Exception e2) {
			throw new InternalErrorException("Error querying domain controllers", e2);
		} finally {
			pool2.returnConnection();
		}
		pool2.setChildPools(children);
	}

	private LDAPPool createChildPool(String base, String host, LDAPPool parent) {
		LDAPPool pool = new LDAPPool();
		pool.setUseSsl( parent.isUseSsl() );
		pool.setBaseDN( base );
		pool.setLdapHost(host);
		pool.setLdapPort( LDAPConnection.DEFAULT_PORT );
		pool.setLdapVersion(parent.getLdapVersion());
		pool.setLoginDN(parent.getLoginDN());
		pool.setPassword(parent.getPassword());
		pool.setAlwaysTrust(parent.isAlwaysTrust());
		pool.setFollowReferrals(parent.isFollowReferrals());
		pool.setDebug (parent.isDebug());
		pool.setLog(parent.getLog());
		pool.setQueryTimeout(getDispatcher().getTimeout() == null ? 5000: getDispatcher().getTimeout());
		return pool;
	}


	protected void handleException(Exception e, LDAPConnection conn) {
		try {
			if (e instanceof LDAPException &&
					conn != null && 
					((LDAPException) e).getResultCode() == LDAPException.CONNECT_ERROR )
			{
				log.warn("Closing failed connection "+conn.toString());
				conn.disconnect();
			}
		} catch (LDAPException e2) {
			log.warn("Error closing connection ", e);
		}
	}



	private void searchDomains(LDAPConnection conn, String excludeDomains) throws Exception {
		
		log.info("CHILD DOMAIN: Searching child domains (excluding "+excludeDomains+") base domain "+baseDN);
		
		String base = baseDN;
		String queryString = "(objectClass=domain)";

		String excluded[] = excludeDomains == null ? 
				new String[0]:
				excludeDomains.trim().toLowerCase().split(" +");
		Arrays.sort(excluded);
		LDAPSearchConstraints constraints = new LDAPSearchConstraints(conn.getConstraints());
		constraints.setReferralFollowing(false);
		
		constraints.setServerTimeLimit(10);
		constraints.setTimeLimit(5000);
		LDAPSearchResults query = conn.search(base,
					LDAPConnection.SCOPE_SUB, queryString, null, false,
					constraints);
		while (query.hasMore()) {
			try {
				LDAPEntry entry = query.next();
				// Ignore embedded domains
				log.info("CHILD DOMAIN: Got entry "+entry.getDN());
			} catch (LDAPReferralException e)
			{
				log.info("CHILD DOMAIN: Referral error "+e.toString());
				for (String r: e.getReferrals())
				{
					try {
						log.info("CHILD DOMAIN: Parsing "+r);
						LDAPUrl url = new LDAPUrl(r);
						String server = url.getHost().toLowerCase();
						String lastPart = server.contains(".") ? server.substring(0, server.indexOf(".")) : server;
						String dn = url.getDN().toLowerCase();
						if ( Arrays.binarySearch(excluded, dn.toLowerCase()) < 0 &&
								Arrays.binarySearch(excluded, server) < 0 &&
								!lastPart.endsWith("dnszones") && 
								!dn.contains("cn=configuration,") &&
								getPool(dn) == null)
						{
							reconfigurePool(server, dn);
						}
					} catch (MalformedURLException e1) {
						log.warn("CHILD DOMAIN: Error decoding "+e.getFailedReferral(), e1);
					}
				}
			}
		}			
		log.info("CHILD DOMAIN: End");
	}

	private void searchLegacyDomains(LDAPConnection conn, String excludeDomains) throws Exception {
		
		log.info("Searching child legacy domains (excluding "+excludeDomains+") base domain "+baseDN);
		
		String base = baseDN;

		String excluded[] = excludeDomains == null ? 
				new String[0]:
				excludeDomains.trim().toLowerCase().split(" +");
		Arrays.sort(excluded);
		LDAPSearchConstraints constraints = new LDAPSearchConstraints(conn.getConstraints());
		constraints.setReferralFollowing(false);
		
		LDAPSearchResults query = conn.search("cn=configuration,"+base,
					LDAPConnection.SCOPE_SUB, "(nETBIOSName=*)", null, false,
					constraints);
		while (query.hasMore()) {
			try {
				LDAPEntry entry = query.next();
				String shortName2 = entry.getAttribute("nETBIOSName").getStringValue().toLowerCase();
				String ncn = entry.getAttribute("nCName").getStringValue().toLowerCase();
				if (! domainToShortName.containsKey(ncn)) {
					log.info("LEGACY DOMAIN: Found legacy domain "+ncn);
					String server;
					if (entry.getAttribute("dnsRoot") != null) {
						server = entry.getAttribute("dnsRoot").getStringValue();
					} else {
						server = "";
						for (String part: ncn.split("dc=")) {
							if (!server.isEmpty()) server += ".";
							if (part.endsWith(",")) server += part.substring(0, part.length()-1);
							else server += part;
						}
					}
					if ( Arrays.binarySearch(excluded, ncn.toLowerCase()) < 0 &&
							Arrays.binarySearch(excluded, server) < 0)
					{
						reconfigurePool(server, ncn, shortName2);
					}
				}
			} catch (LDAPReferralException e)
			{
				log.info("LEGACY DOMAIN: Referral error "+e.toString());
				for (String r: e.getReferrals())
				{
					try {
						log.info("LEGACY DOMAIN: Parsing "+r);
						LDAPUrl url = new LDAPUrl(r);
						String server = url.getHost().toLowerCase();
						String lastPart = server.contains(".") ? server.substring(0, server.indexOf(".")) : server;
						String dn = url.getDN().toLowerCase();
						if ( Arrays.binarySearch(excluded, dn.toLowerCase()) < 0 &&
								Arrays.binarySearch(excluded, server) < 0 &&
								!lastPart.endsWith("dnszones") && 
								!dn.contains("cn=configuration,"))
						{
							reconfigurePool(server, dn);
						}
					} catch (MalformedURLException e1) {
						log.warn("LEGACY DOMAIN: Error decoding "+e.getFailedReferral(), e1);
					}
				}
			} catch (LDAPException e)
			{
				handleException(e, conn);
				log.info("Error getting short domain name "+e.toString(), e);
			}
		}			
		log.info("LEGACY DOMAIN: End");
	}


	/**
	 * Actualiza la contraseña del usuario. Genera la ofuscación SHA-1 y la
	 * asigna al atributo userpassword de la clase inetOrgPerson
	 * 
	 * @param accountName
	 * @throws Exception
	 */
	@SuppressWarnings({ "unchecked", "rawtypes" })
	public void updatePassword(ExtensibleObject sourceObject,
			String accountName, ExtensibleObjects objects, Password password,
			boolean mustchange, boolean enabled) throws Exception {
		log.info("Setting password for "+accountName+" (mustChange="+mustchange+")");
		for (ExtensibleObject object : objects.getObjects()) {
			if (accountName != null)
			{
				if ( multiDomain && accountName.contains("\\"))
					object.setAttribute(SAM_ACCOUNT_NAME_ATTRIBUTE, 
						accountName.split("\\\\")[1]);
				else
					object.setAttribute(SAM_ACCOUNT_NAME_ATTRIBUTE, 
							accountName);
			}
			updateObjectPassword(sourceObject, accountName, object, password,
					mustchange, false, enabled);
		}
	}

	private void updateObjectPassword(ExtensibleObject sourceObject,
			String accountName, ExtensibleObject object, Password password,
			boolean mustchange, boolean delegation, boolean enabled) throws Exception {
		LDAPEntry ldapUser = null;
		LDAPAttribute atributo;
		String samAccount = accountName;
		if (samAccount != null) {
			boolean repeat = false;
			do {
				try {
					if (samAccount != null)
						ldapUser = searchSamAccount(object, samAccount);

					if (ldapUser == null) {
						updateObject(accountName, accountName, object, sourceObject, null /*always apply*/, enabled);
						ldapUser = searchSamAccount(object, samAccount);
					}

					if (ldapUser != null) {
						sourceObject.put("password", password.getPassword());
						sourceObject.put("mustChangePassword", mustchange);
						if (preSetPassword(sourceObject, object, password, ldapUser)) {
							performPasswordChange(ldapUser, accountName, password,
								mustchange, delegation, false, enabled);
							postSetPassword(sourceObject, object, password, ldapUser);
						}
					}
					return;
				} catch (LDAPException e) {
					if (e.getResultCode() == LDAPException.UNWILLING_TO_PERFORM
							&& !repeat) {
						if (e.getLDAPErrorMessage().startsWith("00002035:")) {
							try {
								performPasswordChange(ldapUser, accountName,
										password, mustchange, delegation, true,
										enabled);
								postSetPassword(sourceObject, object, password, ldapUser);
							} catch (Exception e2) {
								String msg = "UpdateUserPassword('" + accountName
										+ "')";
								log.warn(msg + "(First attempt)", e);
								log.warn(msg + "(Second attempt)", e2);
								throw new InternalErrorException(msg
										+ e2.getMessage(), e2);
							}
						}
						else {
							updateObject(accountName, accountName, object, sourceObject, null /*always apply*/, enabled);
							repeat = true;
						}
					} else if (e.getResultCode() == LDAPException.ATTRIBUTE_OR_VALUE_EXISTS) {
						try {
							performPasswordChange(ldapUser, accountName,
									password, mustchange, delegation, true,
									enabled);
							postSetPassword(sourceObject, object, password, ldapUser);
						} catch (Exception e2) {
							String msg = "UpdateUserPassword('" + accountName
									+ "')";
							log.warn(msg + "(First attempt)", e);
							log.warn(msg + "(Second attempt)", e2);
							throw new InternalErrorException(msg
									+ e2.getMessage(), e2);
						}
					} else {
						String msg = "UpdateUserPassword('" + accountName
								+ "')";
						log.warn(msg, e);
						throw new InternalErrorException(msg + e.getMessage(),
								e);
					}
				} catch (Exception e) {
					String msg = "Error UpdateUserPassword('" + accountName
							+ "'). [" + e.getMessage() + "]";
					log.warn(msg, e);
					throw new InternalErrorException(msg, e);
				}
			} while (repeat);
		}
	}

	protected void performPasswordChange(LDAPEntry ldapUser, String accountName,
			Password password, boolean mustchange, boolean delegation,
			boolean replacePassword, boolean enabled) throws Exception {
		
		
		String domain = searchDomainForDN (ldapUser.getDN());
		LDAPConnection conn = getConnection(domain);
		try {
			ArrayList<LDAPModification> modList = new ArrayList<LDAPModification>();
			LDAPAttribute atributo;
			byte b[] = encodePassword(password);
			atributo = new LDAPAttribute("unicodePwd", b);
	
			if ((ldapUser.getAttribute("unicodePwd") == null) && !replacePassword)
				modList.add(new LDAPModification(LDAPModification.ADD, atributo));
			else
				modList.add(new LDAPModification(LDAPModification.REPLACE, atributo));
			// Unlock account
			LDAPAttribute att = ldapUser.getAttribute(USER_ACCOUNT_CONTROL);
			int status = 0;
			if (att != null)
				status = Integer.decode(att.getStringValue()).intValue();
			// Quitar el bloqueo
			status = status & (~ADS_UF_LOCKOUT);
			if (enabled) status = status & (~ADS_UF_ACCOUNTDISABLE);
			// Poner el flag de cambiar en el proximo reinicio
			if (mustchange) {
				if (conn.isTLS())
					modList.add(new LDAPModification(LDAPModification.REPLACE,
						new LDAPAttribute("pwdLastSet", "0")));
	
				status = status | ADS_UF_PASSWORD_EXPIRED;
				status = status & (~ADS_UF_DONT_EXPIRE_PASSWD) & (~ADS_UF_PASSWD_NOTREQD);
			} else {
				status = status & (~ADS_UF_PASSWORD_EXPIRED)  & (~ADS_UF_PASSWD_NOTREQD);
			}
	

			if (delegation)
				status |= ADS_UF_NORMAL_ACCOUNT | ADS_UF_DONT_EXPIRE_PASSWD
						| ADS_UF_TRUSTED_FOR_DELEGATION;
			else
				status = status | ADS_UF_NORMAL_ACCOUNT;
	
			if (!conn.isTLS()){
				updateSamPassword (domain, accountName, password, mustchange);
				modList.clear();
			}
	
			modList.add(new LDAPModification(LDAPModification.REPLACE,
					new LDAPAttribute(USER_ACCOUNT_CONTROL, Integer
							.toString(status))));
			
			// Unlock the user
			if ( ldapUser.getAttribute("lockoutTime") != null &&
				!ldapUser.getAttribute("lockoutTime").getStringValue().equals("0"))
				
				modList.add(new LDAPModification(LDAPModification.REPLACE,
					new LDAPAttribute("lockoutTime", "0")));
			
			log.info("UpdateUserPassword - setting password for user {}",
					accountName, null);
			LDAPModification[] mods = new LDAPModification[modList.size()];
			mods = (LDAPModification[]) modList.toArray(mods);
			debugModifications("Modifying password ", ldapUser.getDN(), mods);
			try {
				conn.modify(ldapUser.getDN(), mods);
			} catch (Exception e) {
				handleException(e, conn);
				throw e;
			}
		} finally {
			returnConnection(domain);
		}
	}

	SMBClient smbClient = null;
	
	private void updateSamPassword(String domain, String accountName, Password password, boolean mustchange) throws IOException, InternalErrorException {
		String hosts = domainHost.get(domain);
		if (accountName.contains("\\"))
			accountName = accountName.substring(accountName.indexOf("\\")+1);
//		String ntDomain = domainToShortName.get(domain);
		if (hosts == null) hosts = domain;
		for (String host: hosts.split(" +"))
		{
			final Connection smbConnection = smbClient.connect(host == null ? domain: host);
			try {
			    final AuthenticationContext smbAuthenticationContext = new AuthenticationContext(
			    		this.samAccountName, this.password.getPassword().toCharArray(), this.samDomainName);
			    final Session session = smbConnection.authenticate(smbAuthenticationContext);
			    final RPCTransport transport2 = SMBTransportFactories.SAMSVC.getTransport(session);
			    SamrService sam = new SamrService(transport2, session);
			    ServerHandle server = sam.openServer();
			    MembershipWithName[] domains = sam.getDomainsForServer(server);
			    for (MembershipWithName n: domains)
			    {
				    SID sid = sam.getSIDForDomain(server, n.getName());
			    	DomainHandle domainHandle = sam.openDomain(server, sid);
			    	if (debugEnabled)
			    		log.info("Searching user "+accountName+" at SAM domain "+n.getName());
			    	int [] r;
			    	try {
			    		r = sam.lookupNames(domainHandle, new String[] {accountName});
			    	} catch (RPCException e) {
			    		if (e.getErrorCode() == SystemErrorCode.STATUS_NONE_MAPPED)
			    			continue;
			    		else
			    			throw e;
			    	}
			    	for (int i: r) {
			    		if (debugEnabled)
			    			log.info("Opening user "+accountName+" at SAM domain "+n.getName());
			    		UserHandle userHandle = sam.openUser(domainHandle, i, 0x201DB);
			    		try {
				    		UserAllInformation userAllInformation = sam.getUserAllInformation(userHandle);
				    		if (debugEnabled)
				    			log.info("Setting password for user "+accountName+" at SAM domain "+n.getName());
							sam.setPasswordEx(userHandle, password.getPassword(), mustchange);
							return;
				    	} catch (RPCException e) {
				    		if (e.getErrorCode() != null && e.getErrorCode().is( 0xC000006C) ) {
				    			throw new InternalErrorException("The password is not accepted due to policy restrictions", e);
				    		} else {
				    			throw e;
				    		}
			    		} finally {
			    			sam.closeHandle(userHandle);
			    		}
			    	}		    	
			    }
			} finally {
				smbConnection.close();
			}
		}
	}

	protected String searchDomainForDN(String dn) {
		if ( ! multiDomain )
			return mainDomain;
		
		long length = 0;
		String selected = null;
		for (String domain: domainHost.keySet())
		{
			if (dn.toLowerCase().endsWith(domain.toLowerCase()) && domain.length() > length)
			{
				length = domain.length();
				selected = domain;
			}
		}
		return selected;
	}

	protected String searchNTDomainForDN(String dn) {
		String domain = searchDomainForDN(dn);
		return domainToShortName.get(domain);
	}

	protected LDAPEntry searchSamAccount(ExtensibleObject object,
			String samAccount) throws Exception {
		return searchSamAccount(object, samAccount, false);
	}
	
	protected LDAPEntry searchSamAccount(ExtensibleObject object,
			String samAccount, boolean deletedObjects) throws Exception {
		String dn = vom.toSingleString(object
				.getAttribute("dn"));
		String objectClass = vom.toSingleString(object
				.getAttribute("objectClass"));
		String queryString = "(&";
		
		if (dn != null)
		{
			LDAPEntry entry = searchEntry( dn );
			if (entry != null) return entry;
		}
		
		Map<String, String> props = getProperties ( object.getObjectType());
		String key = props.get("key");
		if (key == null)
			key = SAM_ACCOUNT_NAME_ATTRIBUTE;

		if (samAccount != null &&
				objectClass != null)
		{
			LDAPEntry entry = findSamObject(objectClass, key, samAccount, deletedObjects);
			return entry;
		}
		
		for (String att: object.getAttributes())
		{
			try {
				if ( !att.equals("relativeBaseDn") && ! att.equals("dn"))
				{
					String value = vom.toSingleString(object.getAttribute(att));
					queryString = queryString + "("+att +"="+ escapeLDAPSearchFilter(value) + ")";
				}
			} catch (Exception e) 
			{
			}
		}
		queryString = queryString + ")";

		for (String domain: domainHost.keySet())
		{
			if (debugEnabled)
				log.info("Looking for object "+samAccount+": LDAP QUERY="
						+ queryString.toString() + " on " + domain);
			LDAPConnection conn = getConnection(domain);
			try {
				LDAPSearchConstraints constraints = new LDAPSearchConstraints(conn.getConstraints());
				LDAPSearchResults query = conn.search(domain,
						LDAPConnection.SCOPE_SUB, queryString, null, false,
						constraints);
				while (query.hasMore()) {
					try {
						LDAPEntry entry = query.next();
						return entry;
					} catch (LDAPReferralException e) {
						if (followReferrals)
							throw e;
					}
				}
			} catch (LDAPException e) {
				handleException(e, conn);
				throw e;
			} finally {
				returnConnection(domain);
			}
		}

		return null;
	}

	/**
	 * Busca los datos de un usuario en el directorio LDAP
	 * 
	 * @param user
	 *            codigo del usuario
	 * @return LDAPEntry entrada del directorio LDAP
	 * @throws Exception
	 */
	private LDAPEntry searchEntry(String dn) throws Exception {
		String domain = searchDomainForDN(dn);
		LDAPConnection connection = getConnection(domain);
		try {
			return connection.read(dn);
		} catch (LDAPReferralException e) {
			if (followReferrals)
				throw e;
			else
				return null;
		} catch (LDAPException e) {
			if (e.getResultCode() == LDAPException.NO_SUCH_OBJECT )
				return null;
			handleException(e, connection);
			String msg = "serchEntry ('" + dn
					+ "'). Error finding entry. [" + e.getMessage()
					+ "]";
			log.warn(msg, e);
			throw new InternalErrorException(msg, e);
		} finally {
			returnConnection(domain);
		}
	}

	/**
	 * Busca los datos de un usuario en el directorio LDAP
	 * 
	 * @param user
	 *            codigo del usuario
	 * @return LDAPEntry entrada del directorio LDAP
	 * @throws Exception
	 */
	private LDAPEntry searchEntry(String dn, String attributes[]) throws Exception {
		String domain = searchDomainForDN(dn);
		LDAPConnection connection = getConnection(domain);
		try {
			return connection.read(dn, attributes);
		} catch (LDAPReferralException e) {
			if (followReferrals)
				throw e;
			else
				return null;
		} catch (LDAPException e) {
			if (e.getResultCode() == LDAPException.NO_SUCH_OBJECT)
				return null;
			handleException(e, connection);
			String msg = "buscarUsuario ('" + dn
					+ "'). Error al buscar el usuario. [" + e.getMessage()
					+ "]";
			log.warn(msg, e);
			throw new InternalErrorException(msg, e);
		} finally {
			returnConnection(domain);
		}
	}

	private String[] toStringArray(Object obj) {
		if (obj == null)
			return null;
		else if (obj instanceof String[]) {
			return (String[]) obj;
		} else if (obj instanceof Object[]) {
			return vom.toStringArray((Object[]) obj);
		} else {
			return new String[] { vom.toString(obj) };
		}
	}

	Map<String, String> getProperties (String objectType) {
		if (objectMappings != null)
		{
			for ( ExtensibleObjectMapping om: objectMappings)
			{
				if (om.getSystemObject().equals(objectType))
					return om.getProperties();
			}
		}
		return new HashMap<String,String>();
	}
	/**
	 * Añade los datos de un usuario al directorio LDAP
	 * 
	 * @param accountName
	 * @param source
	 * @param changes 
	 * 
	 * @param usuario
	 *            Informacion del usuario
	 * @throws Exception
	 */
	public void updateObjects(String accountName, String newAccountName, ExtensibleObjects objects,
			ExtensibleObject source, List<String[]> changes,
			boolean enabled) throws Exception {

		for (ExtensibleObject object : objects.getObjects()) {
			Map<String, String> props = getProperties ( object.getObjectType());
			String key = props.get("key");
			if (key == null)
				key = SAM_ACCOUNT_NAME_ATTRIBUTE;
			if (newAccountName != null)
			{
				if ( multiDomain && newAccountName.contains("\\"))
					object.setAttribute(key, 
						newAccountName.split("\\\\")[1]);
				else
					object.setAttribute(key, 
							newAccountName);
			}
			else if (accountName != null)
			{
				if ( multiDomain && accountName.contains("\\"))
					object.setAttribute(key, 
						accountName.split("\\\\")[1]);
				else
					object.setAttribute(key, 
							accountName);
			}
			if (isDebug()) {
				if (accountName.equals(newAccountName))
					log.info("BEGIN Updating object {}", accountName);
				else
					log.info("BEGIN Updating object {} (new name is {})", accountName, newAccountName);
			}
			updateObject(accountName, newAccountName, object, source, changes, enabled);
			if (isDebug())
				log.info("END");
		}
	}

	private String[] splitDN (String dn)
	{
		List <String> s = new LinkedList<String>();
		int start = 0;
		int i = 1;
		do
		{
			i = dn.indexOf(",", i);
			if (i < 0)
			{
				s.add(dn.substring(start));
				break;
			}
			if (i > 0 && dn.charAt(i-1) != '\\')
			{
				s.add( dn.substring(start, i));
				start = i+1;
			}
			i ++;
		} while (true);
		return s.toArray(new String[s.size()]);
	}
	
	private String getDN(ExtensibleObject object, String accountName) throws InternalErrorException {
		String dn = (String) object.getAttribute("dn");
		if (dn == null || dn.length() == 0) {
			String name = (String) object.getAttribute("cn");
			if (name == null) name = "";
			else name = name.trim();
			name = "cn=" + name.replaceAll(",", "\\\\,");
			if (object.getAttribute(RELATIVE_DN) != null)
			{
				String base = getAccountDomain(accountName, dn);
				String rbdn = (String) object.getAttribute(RELATIVE_DN);
				return name + "," + (rbdn.trim().isEmpty()? "" : rbdn +",")+base;
			}
			else if (object.getAttribute(BASE_DN) != null)
				return name + "," + object.getAttribute(BASE_DN);
			else
				return name + "," + baseDN;
		} else
			return dn;
	}

	private void createParents(String dn) throws Exception {
		createParents ( splitDN(dn), 0);
	}
	
	private void createParents (String[] parts, int position) throws Exception
	{
		if (position >= parts.length)
			return; 
		String dn = mergeDN(parts, position);
		String domain = searchDomainForDN(dn);
		if (dn.equalsIgnoreCase(domain))
			return;

		if (debugEnabled)
			log.info("BEGIN Checking parent object "+dn);
		boolean found = false;
		LDAPConnection connection = getConnection(domain);
		try {
			connection.read( dn );
			found = true;
		} catch (LDAPReferralException e) {
			if (followReferrals)
				throw e;
		} catch (LDAPException e) {
			if (e.getResultCode() != LDAPException.NO_SUCH_OBJECT) {
				throw new InternalErrorException ("Error reading "+ dn,e);
			}
			handleException(e, connection);
		} finally {
			returnConnection(domain);
		}

		if (!found) {
			if ( ! createOUs)
				throw new InternalErrorException("Creation of parent object is disabled by configuration settings: "
						+ dn);
			createParents(parts, position + 1);
			LDAPAttributeSet attributeSet = new LDAPAttributeSet();

			String name = parts[position].replaceAll("\\\\", "");
			if (name.contains("="))
				name = name.substring(name.indexOf("=")+1);
			if (dn.toLowerCase().startsWith("ou=")) {
				attributeSet.add(new LDAPAttribute("objectclass",
						"organizationalUnit"));
				attributeSet.add(new LDAPAttribute("ou", name));
			} else {
				throw new InternalErrorException("Unable to create object "
						+ dn);
			}
			LDAPEntry entry = new LDAPEntry(dn, attributeSet);
			try {
				log.info("Creating " + dn );
				log.info("ou name = " + name );
				connection.add(entry);
			} finally {
				returnConnection(domain);
			}
		}
		log.info("END");
	}


	private String mergeDN(String[] parts, int position) {
		String dn = "";
		for (int i = position; i < parts.length; i++)
		{
			if ( i > position ) dn += ",";
			dn += parts[i];
		}
		return dn;
	}

	protected void updateObject(String accountName, String newAccountName, ExtensibleObject object,
			ExtensibleObject source, List<String[]> changes,
			boolean enabled) throws Exception {
		
		String actualAccountName = newAccountName;
		String dn = getDN(object, actualAccountName);
		String domain = getAccountDomain(newAccountName, dn);
		LDAPConnection conn = getConnection(domain);
		String domain0 = domain;
		String domain1 = null;
		Map<String, String> props = getProperties ( object.getObjectType());
		String key = props.get("key");
		if (key == null)
			key = SAM_ACCOUNT_NAME_ATTRIBUTE;

		try {
			LDAPEntry entry = null;
			if (isDebug())
				log.info("BEGIN Searching for AD object");

			if (debugEnabled)
				debugObject("Object attributes " + newAccountName, object, "  ");
			entry = searchSamAccount(object, newAccountName);
			if (entry == null && ! newAccountName.equals(accountName))
			{
				entry = searchSamAccount(object, accountName);
				if (entry != null)
				{
					actualAccountName = accountName;
					dn = getDN(object, accountName);
					domain1 = domain = getAccountDomain(accountName, dn);
					conn = getConnection(domain);
				}
			}
			if (entry == null && "true".equals(extendedAttributes.get("undelete"))) { // Try to undelete it
				entry = searchSamAccount(object, newAccountName, true);
				if (entry != null) { //Undelete
					log.info("Previously deleted object not found -> Undeleting it");
					conn = getConnection(domain);
					LDAPConstraints constraints = conn.getConstraints();
					constraints.setControls( 
							new LDAPControl [] {new LDAPControl ("1.2.840.113556.1.4.528", true, null)});
					conn.modify(entry.getDN(), new LDAPModification[] {
							new LDAPModification(LDAPModification.DELETE, new LDAPAttribute("isDeleted")),
							new LDAPModification(LDAPModification.REPLACE, new LDAPAttribute("distinguishedName", dn)),
					}, constraints);
					entry = conn.read(dn);
				}
			}
			if (entry == null) {
				if (isDebug()) {
					log.info("Object not found -> Create it");
					log.info("END");
				}
				if (changes != null)
					changes.add( new String[] {"Create", dn} );
				else
					createNewObject(conn, actualAccountName, dn, object, source, enabled);
			} else {
				if (isDebug()) {
					log.info("Object found -> Update it");
					log.info("END");
				}
				updateExistingObject(conn, entry, actualAccountName, dn, object, source, changes);
			}
		} catch (Exception e) {
			String msg = "updating object : " + accountName;
			log.warn(msg, e);
			handleException(e, conn);
			throw new InternalErrorException(msg, e);
		} finally {
			returnConnection(domain0);
			if (domain1 != null)
				returnConnection(domain1);
		}
	}


	private void updateExistingObject(LDAPConnection conn, LDAPEntry entry, String accountName, String dn,
			ExtensibleObject object, ExtensibleObject source, List<String[]> changes)
			throws InternalErrorException, UnsupportedEncodingException, IOException, Exception, LDAPException {
		log.info("Update existing object");
		boolean modifyuserPrincipalName = false;
		Boolean userCannotChangePassword = null;
		if (changes != null || preUpdate(source, object, entry)) {
			LinkedList<LDAPModification> modList = new LinkedList<LDAPModification>();
			if (isDebug())
				log.info("BEGIN Updating Active Directory Object");
			for (String attribute : object.getAttributes()) {
				Object ov = object.getAttribute(attribute);
				if (ov != null && "".equals(ov))
					ov = null;
				if ("userCannotChangePassword".equals(attribute)) {
					userCannotChangePassword = ov != null && 
							ov.toString().equalsIgnoreCase("true");
				}
				else if (!"dn".equals(attribute)
						&& !"objectClass".equals(attribute)
						&& !BASE_DN.equals(attribute)
						&& !RELATIVE_DN.equals(attribute)) {
					String[] value = toStringArray(object.getAttribute(attribute));
					if (value != null && value.length == 0)
					{
						ov = null;
						value = null;
					}
					LDAPAttribute previous = entry.getAttribute(attribute);
					if (ov == null
							&& previous != null) {
						modList.add(new LDAPModification(
								LDAPModification.DELETE,
								new LDAPAttribute(attribute)));
					}
					else if (attribute.equals( SAM_ACCOUNT_NAME_ATTRIBUTE) && ov instanceof String)
					{
						String old = previous == null ? null : 
								previous.getStringValue();
						if ( old == null || differentAccountName((String)ov, old))
						{
							modList.add(new LDAPModification(
									previous == null ? LDAPModification.ADD: LDAPModification.REPLACE,
										new LDAPAttribute(attribute, (String) ov)));
						}
					} 
					else if (attribute.equals("userParameters") && ov instanceof Map)
					{
						AttributesEncoder e = new AttributesEncoder(previous == null? null: previous.getByteValue());
						Map<String,String> ovMap = (Map<String,String>) ov;
						for (String s : ovMap.keySet())
						{
							e.put(s, ovMap.get(s));
						}
						modList.add(new LDAPModification(
								previous == null ? LDAPModification.ADD: LDAPModification.REPLACE,
									new LDAPAttribute(attribute,
											e.getBytes())));
					} else if (ov != null
							&& previous == null) {
						if (ov instanceof byte[]) {
							modList.add(new LDAPModification(
									LDAPModification.ADD,
									new LDAPAttribute(attribute,
											(byte[]) ov)));
						} else {
							if (attribute.equals("userPrincipalName"))
								modifyuserPrincipalName = true;
							modList.add(new LDAPModification(
									LDAPModification.ADD,
									new LDAPAttribute(attribute, value)));
						}
					} else if ((ov != null)
							&& (previous != null)
							&& !"cn".equalsIgnoreCase(attribute)) {
						if (value.length != 1 ||
								previous.getStringValueArray().length != 1 ||
								!value[0].equals(previous.getStringValue())) {
							if (ov instanceof byte[])
								modList.add(new LDAPModification(
										LDAPModification.REPLACE,
										new LDAPAttribute(attribute,
												(byte[]) ov)));
							else {
								if (attribute.equals("userPrincipalName"))
									modifyuserPrincipalName = true;
								modList.add(new LDAPModification(
										LDAPModification.REPLACE,
										new LDAPAttribute(attribute,
												value)));
							}
						}
					}
				}
			}

			if (changes != null && modList.size() > 0)
			{
				for ( LDAPModification mod: modList)
				{
					String newValue = mod.getAttribute().getStringValue();
					if (mod.getOp() == LDAPModification.DELETE)
					{
						String oldValue = entry.getAttribute(mod.getAttribute().getName()).getStringValue();
						changes.add(new String [] {"Remove attribute "+mod.getAttribute().getName(), oldValue, ""});
					}
					if (mod.getOp() == LDAPModification.REPLACE)
					{
						String oldValue = entry.getAttribute(mod.getAttribute().getName()).getStringValue();
						changes.add(new String [] {"Update attribute "+mod.getAttribute().getName(), oldValue, newValue });
					}
					if (mod.getOp() == LDAPModification.ADD)
					{
						changes.add(new String [] {"Add attribute "+mod.getAttribute().getName(), "", newValue,});
					}
				}
			}
			else if (modList.size() > 0) {
				if (modifyuserPrincipalName) {
					// Temporary patch
					String upn = vom.toSingleString(object.getAttribute("userPrincipalName"));
					String objectClass = vom.toSingleString(object
							.getAttribute("objectClass"));
					if (upn != null && objectClass != null)
					{
						LDAPEntry entry2 = findUpnObject (objectClass, upn);
						if (entry2 != null && ! entry2.getDN().equals(entry.getDN()))
						{
							log.info("Moving userPrincipalName from "+entry2.getDN()+" to "+entry.getDN());
							LDAPModification[] mods2 = new LDAPModification[] {
									new LDAPModification(
											LDAPModification.DELETE,
											new LDAPAttribute("userPrincipalName", upn))
							};
							conn.modify(entry2.getDN(), mods2);
						}
					}
				}				
				LDAPModification[] mods = new LDAPModification[modList
						.size()];
				mods = (LDAPModification[]) modList.toArray(mods);
				debugModifications("Modifying object ", entry.getDN(),
						mods);
				conn.modify(entry.getDN(), mods);
				if (userCannotChangePassword != null)
					applySamChangeForEnablePasswordChange(conn, accountName, 
							entry.getDN(), userCannotChangePassword);
				postUpdate(source, object, entry);
			} else {
				if (userCannotChangePassword != null)
					applySamChangeForEnablePasswordChange(conn, accountName, 
							entry.getDN(), userCannotChangePassword);
				postUpdate(source, object, entry);
				
			}

			LdapName n = new LdapName(dn.toLowerCase());
			LdapName n2 = new LdapName(entry.getDN().toLowerCase());
			if (!n.equals(n2)
					&& !entry.getDN().contains(",CN=Builtin,")) {
				if (isDebug())
					log.info("BEGIN Distinguished Name change detected");

				// Check if must rename
				boolean rename = true;
				ExtensibleObjectMapping mapping = getMapping(object
						.getObjectType());
				if (mapping != null) {
					rename = !"false".equalsIgnoreCase(mapping
							.getProperties().get("rename"));
				}
				if (rename) {
					if (changes != null)
					{
						changes.add(new String[] {"Rename", entry.getDN(), dn});
					}
					else
					{
						log.info("Renaming from "+entry.getDN()+" to "+dn);
						String[] split = splitDN(dn);
						createParents(split, 1);
						String parentName =  mergeDN(split, 1);
						LDAPEntry oldEntry = searchEntry(dn);
						if (oldEntry != null)
						{
							log.info("Moving away old object "+dn);
							conn.rename(dn, split[0]+" - old "+System.currentTimeMillis(),
									parentName, true);
							
						}
						entry = conn.read(entry.getDN());
						conn.rename(entry.getDN(), split[0],
								parentName, true);
					}
				}
				if (isDebug())
					log.info("BEGIN Distinguished Name change detected");
			}
			if (isDebug())
				log.info("END");
		}
	}


	private void applySamChangeForEnablePasswordChange(LDAPConnection conn, String accountName, 
			String dn, Boolean userCannotChangePassword) 
			throws IOException, InternalErrorException, LDAPException {
		LDAPEntry ee = conn.read(dn, new String[] {"nTSecurityDescriptor"});
		try {
			final LDAPAttribute attribute = ee.getAttribute("nTSecurityDescriptor");
			ACE aceEveryone = null;
			ACE aceSelf = null;
			if (attribute == null) {
				throw new InternalErrorException("Cannot retrieve ntSecurityDescriptor");
			}
			SMBBuffer buff = new SMBBuffer(attribute.getByteValue());
			d = SecurityDescriptor.read(buff);
			for (ACE ace: d.getDacl().getAces()) {
				if (ace.getAceHeader().getAceType() == AceType.ACCESS_DENIED_OBJECT_ACE_TYPE &&
						ace instanceof AceType2 &&
						((AceType2)ace).getObjectType().toString().equals(PASSWORD_OBJECT) &&
						ace.getAccessMask() == AccessMask.FILE_WRITE_ATTRIBUTES.getValue()) {
					if (ace.getSid().toString().equals(SID_SELF)) 
						aceSelf = ace;
					if (ace.getSid().toString().equals(SID_EVERYONE)) 
						aceEveryone = ace;
				}
			}
			if ((aceSelf != null || aceEveryone != null) && ! userCannotChangePassword) {
				d.getDacl().getAces().remove(aceSelf);
				d.getDacl().getAces().remove(aceEveryone);
				SMBBuffer outBuffer = new SMBBuffer();
				d.write(outBuffer);
				log.info("Changing NTSecurityDescriptor to allow password changes");
				conn.modify(ee.getDN(), 
						new LDAPModification(
								LDAPModification.REPLACE,
								new LDAPAttribute("nTSecurityDescriptor", outBuffer.array())));
			}
			else if ((aceSelf == null || aceEveryone == null) && userCannotChangePassword) {
				log.info("Changing NTSecurityDescriptor to prevent password changes");
				if (aceSelf == null)
					d.getDacl().getAces().add(
						AceTypes.accessDeniedObjectAce(
								new HashSet<>(),
								EnumSet.of(AccessMask.FILE_WRITE_ATTRIBUTES),
								UUID.fromString(PASSWORD_OBJECT),
								(UUID) null,
								com.hierynomus.msdtyp.SID.fromString(SID_SELF)));
				if (aceEveryone != null)
					d.getDacl().getAces().add(
						AceTypes.accessDeniedObjectAce(
								new HashSet<>(),
								EnumSet.of(AccessMask.FILE_WRITE_ATTRIBUTES),
								UUID.fromString(PASSWORD_OBJECT),
								(UUID) null,
								com.hierynomus.msdtyp.SID.fromString(SID_EVERYONE)));
				SMBBuffer outBuffer = new SMBBuffer();
				d.write(outBuffer);
				conn.modify(ee.getDN(), 
						new LDAPModification(
								LDAPModification.REPLACE,
								new LDAPAttribute("nTSecurityDescriptor", outBuffer.array())));
			}
		} catch (Exception e) {
			throw new InternalErrorException("Error parsig ntSecurityDescriptor", e);
		}
	}


	protected boolean differentAccountName(String ov, String old) {
		return ! removeAccents(old).equalsIgnoreCase( removeAccents(ov) );
		
	}

	

	private String removeAccents(String string) {
		return string.toLowerCase();
//        StringBuilder sb = new StringBuilder(string.length());
//        string = Normalizer.normalize(string.toLowerCase(), Normalizer.Form.NFD);
//        for (char c : string.toCharArray()) {
//            if (c <= '\u007F') sb.append(c);
//        }
//        return sb.toString();
    }	


	private void createNewObject(LDAPConnection conn, String accountName, String dn, ExtensibleObject object,
			ExtensibleObject source, boolean enabled)
			throws InternalErrorException, Exception, UnsupportedEncodingException, IOException, LDAPException {
		LDAPEntry entry;
		if (preInsert(source, object)) {
			if (isDebug())
				log.info("Create Active Directory object");
			LDAPAttributeSet attributeSet = new LDAPAttributeSet();
			for (String attribute : object.getAttributes()) 
			{
				Object ov = object.getAttribute(attribute);
				if (ov != null
						&& !"".equals(ov)
						&& !"dn".equals(attribute)
						&& !BASE_DN.equals(attribute)
						&& !RELATIVE_DN.equals(attribute)) {
					if (attribute.equals("manager"))
					{
						String values[] = toStringArray(object
								.getAttribute(attribute));
						checkDnAttributes(values);
						attributeSet.add(new LDAPAttribute(attribute,
								values));
					}
					else if (attribute.equals("userParameters") && ov instanceof Map)
					{
						AttributesEncoder e = new AttributesEncoder(null);
						Map<String,String> ovMap = (Map<String,String>) ov;
						for (String s : ovMap.keySet())
						{
							e.put(s, ovMap.get(s));
						}
						attributeSet.add(new LDAPAttribute(attribute,
								e.getBytes()));
					}
					else if (ov instanceof byte[]) {
						attributeSet.add(new LDAPAttribute(attribute,
								(byte[]) ov));
					} else {
						String values[] = toStringArray(object
								.getAttribute(attribute));
						attributeSet.add(new LDAPAttribute(attribute,
								values));
					}
				}
			}


			if (object.getAttribute(USER_ACCOUNT_CONTROL) == null) {
				if ("user".equalsIgnoreCase((String) object.getAttribute("objectClass"))) {
					if (isDebug())
						log.info("Setting default userAccountControl value");
					attributeSet.add(new LDAPAttribute(
							USER_ACCOUNT_CONTROL, Integer
									.toString(ADS_UF_ACCOUNTDISABLE
											+ ADS_UF_NORMAL_ACCOUNT)));
				}
			}

			String[] split = splitDN(dn);
			createParents(split, 1);
			debugModifications("Adding user", dn, attributeSet);
			entry = new LDAPEntry(dn, attributeSet);
			conn.add(entry);
			postInsert(source, object, entry);
			if (accountName != null
					&& "user".equalsIgnoreCase((String) object.getAttribute("objectClass"))) {
				if (isDebug())
					log.info("BEGIN Setting initial password");
				Password p = getServer().getAccountPassword(
						accountName, getCodi());
				if (p != null) {
					updateObjectPassword(source, accountName, object,
							p, false, false, enabled);
				} else {
					p = getServer().generateFakePassword(accountName,
							getCodi());
					updateObjectPassword(source, accountName, object,
							p, true, false, enabled);
				}
				if (isDebug())
					log.info("END");
			}
		}
	}


	private String getAccountDomain(String accountName, String dn) throws InternalErrorException {
		if (accountName == null)
			return searchDomainForDN(dn);
		String d;
		String ntDomain;
		String[] domainSplit = accountName.split("\\\\");
		if (multiDomain && domainSplit.length == 2)
		{
			ntDomain = domainSplit[0].toLowerCase();
			d = shortNameToDomain.get(ntDomain);
			if (d == null)
				throw new InternalErrorException("Unable to find domain for "+ntDomain);
		}
		else if (dn == null)
			d = mainDomain;
		else {
			d = searchDomainForDN(dn);
			if (d == null)
				throw new InternalErrorException("Unable to find domain for "+dn);
		}
		return d;
	}


	private void checkDnAttributes(String[] values) throws Exception {
		LDAPEntry entry;
		if (values != null)
		{
			for (int i = 0; i < values.length; i++)
			{
				String s = values[i];
				while (!s.isEmpty())
				{
					entry = searchEntry(s);
					if (entry == null)
					{
						int p = s.indexOf(',');
						if (p > 0)
							s = s.substring(p+1);
						else
							s = "";
					}
					else
						break;
				}
				values[i] = s;
			}
		}
	}

	private ExtensibleObjectMapping getMapping(String objectType) throws InternalErrorException {
		ExtensibleObjectMapping m = null;
		for (ExtensibleObjectMapping map : objectMappings) {
			if (map.getSystemObject().equals(objectType))
				if (m == null) m = map;
				else throw new InternalErrorException("There is more than one mapping for system object "+objectType+". Please, rename one of them");
		}
		return m;
	}

	public void removeObjects(String account, ExtensibleObjects objects,
			ExtensibleObject source, List<String[]> changes) throws Exception {		
		for (ExtensibleObject object : objects.getObjects()) {
			LDAPEntry entry;
			try {
				entry = searchSamAccount(object, account);
			} catch (Exception e1) {
				String msg = "Error searching for object " + account;
				log.warn(msg, e1);
				throw new InternalErrorException(msg, e1);
			}
			if (entry != null) {
				if (changes != null)
				{
					changes.add(new String [] { "Remove account", entry.getDN()});
				}
				else if (preDelete(source, entry)) {
					String dn = entry.getDN();
					String domain = searchDomainForDN(dn);
					LDAPConnection conn = getConnection(domain);
					try {
						log.info("Removing object {}", dn, null);
						updateLastLogon(source, object, entry);
						LinkedList<String> dns = new LinkedList<String>();
						dns.add(dn);
						LDAPSearchResults search = conn.search(dn,
								LDAPConnection.SCOPE_SUB, "", null, false);
						while (search.hasMore()) {
							try {
								entry = search.next();
								if (!dns.contains(entry.getDN()))
								{
									dns.add(entry.getDN());
								}
							} catch (LDAPReferralException ldapError) {
								if (followReferrals)
									throw ldapError;
							}
						}
						Collections.sort(dns, new Comparator<String>() {
							public int compare(String o1, String o2) {
								return o2.length() - o1.length();
							}
						});
						for (String d: dns)
						{
							log.info("About to recursively remove "+d);
							LDAPConstraints c = conn.getConstraints();
							LDAPControl recursivelyDelete = new LDAPControl ("1.2.840.113556.1.4.805", true, null);
//							LDAPControl recursivelyDeleteEx = new LDAPControl ("1.2.840.113556.1.4.2204", true, "16384".getBytes());
							c.setControls(new LDAPControl[] {
								recursivelyDelete
//								recursivelyDeleteEx
							});
							try {
								conn.delete(d, c);
							} catch (LDAPException e) {
								if (d.equals(dn)) throw e;
							}
						}
						postDelete(source, entry);
					} catch (Exception e) {
						String msg = "updating object : " + dn;
						log.warn(msg, e);
						handleException(e, conn);
						throw new InternalErrorException(msg, e);
					} finally {
						returnConnection(domain);
					}
				}
			}
		}
	}

	private void updateLastLogon(ExtensibleObject source, ExtensibleObject object, LDAPEntry entry) throws InternalErrorException, AccountAlreadyExistsException, IOException {
		String accountName = (String) source.getAttribute("accountName");
		if (accountName != null)
		{
			for ( ExtensibleObjectMapping mapping: objectTranslator.getObjects())
			{
				if (mapping.getSystemObject().equals(object.getObjectType()))
				{
					LDAPExtensibleObject entry2 = new LDAPExtensibleObject(mapping.getSystemObject(), entry, getEntryPool(entry));
					AccountService accountService = new RemoteServiceLocator().getAccountService();
					com.soffid.iam.api.Account account = accountService.findAccount(accountName, getCodi());
					if (account != null)
					{
						ExtensibleObject translated = objectTranslator.parseInputObject(entry2, mapping);
						if (translated != null)
						{
							Account account2 = vom.parseAccount(translated);
							if (account2 != null)
							{
								account.setLastLogin(account2.getLastLogin());
								account.setLastPasswordSet(account2.getLastPasswordSet());
								accountService.updateAccount(account);
							}
						}
					}
					
				}
			}
		}
	}


	private LDAPEntry findSamAccount(String user) throws Exception {
		return findSamObject("user", SAM_ACCOUNT_NAME_ATTRIBUTE, user);
	}

	private LDAPEntry findSamObject(String objectClass, String key, String value) throws Exception {
		return findSamObject(objectClass, key, value, false);
	}
	
	private LDAPEntry findSamObject(String objectClass, String key, String value, boolean deletedObjects) throws Exception {
		LDAPEntry entry;
		String queryString;
		
		String domain = mainDomain;
		String samAccountName = value;
		
		String[] domainSplit = value.split("\\\\");
		if (multiDomain && domainSplit.length == 2)
		{
			String ntDomain = domainSplit[0].toLowerCase();
			log.info("findSamObject: nt domain "+ntDomain);
			domain = shortNameToDomain.get(ntDomain);
			log.info("findSamObject: domain "+ntDomain);
			if (domain == null)
				throw new InternalErrorException("Searching for object "+value+" on unknown domain "+domainSplit[0]);
			samAccountName = domainSplit[1];
			
		}
		queryString = "(&(objectClass=" + objectClass + ")("+key+"=" + escapeLDAPSearchFilter(samAccountName) + "))";

		LDAPConnection conn = getConnection(domain);

		LDAPSearchConstraints constraints = new LDAPSearchConstraints(conn.getConstraints());
		if (deletedObjects) {
			constraints.setControls( 
					new LDAPControl [] {
						new LDAPControl ("1.2.840.113556.1.4.417", true, null)
					});
		}
		
		try {
			if (debugEnabled)
				log.info("Searching for object "+queryString+" on domain "+domain+" ("+domain+")");
			LDAPSearchResults search = conn.search(domain,
					LDAPConnection.SCOPE_SUB, queryString, null, false,
					constraints);
			while (search.hasMore()) {
				try {
					entry = search.next();
					return entry;
				} catch (LDAPReferralException ldapError) {
					if (followReferrals)
						throw ldapError;
				}
			}
			return null;
		} catch (LDAPException e) {
			handleException(e, conn);
			throw e;
		} finally {
			returnConnection(domain);
		}
	}

	private LDAPEntry findUpnObject(String objectClass, String upn) throws Exception {
		LDAPEntry entry;
		String queryString;

		for ( String domain: domainHost.keySet())
		{
			queryString = "(&(objectClass=" + objectClass + ")(userPrincipalName=" + escapeLDAPSearchFilter(upn) + "))";
			LDAPConnection conn = getConnection(domain);
			try {
				if (debugEnabled)
					log.info("Searching for object "+queryString+" on domain "+domain+" ("+domain+")");
				LDAPSearchConstraints constraints = new LDAPSearchConstraints(conn.getConstraints());
				LDAPSearchResults search = conn.search(domain,
						LDAPConnection.SCOPE_SUB, queryString, null, false,
						constraints);
				while (search.hasMore()) {
					try {
						entry = search.next();
						return entry;
					} catch (LDAPReferralException ldapError) {
						if (followReferrals)
							throw ldapError;
					}
				}
			} catch (LDAPException e) {
				handleException(e, conn);
				throw e;
			} finally {
				returnConnection(domain);
			}
		}
		return null;
	}

	@Override
	public boolean validateUserPassword(String user, Password password)
			throws RemoteException, InternalErrorException {
		log.info("Validating password for "+user+" en "+ldapHost);
		String[] ldapHosts = ldapHost.split("[, ]+");
		LDAPEntry entry;
		try {
			entry = findSamAccount(user);
		} catch (Exception e1) {
			log.warn("Error searching account "+user, e1);
			return false;
		}
		if (entry == null) {
			return false;
		}
		LDAPConnection conn = null;
		for (String host : ldapHosts) {
			Watchdog.instance().interruptMe(getDispatcher().getTimeout());
			try {

				log.info("Creating connection");
				conn = createConnection ();				
				try {
					log.info("Connecting");
					conn.connect(host, ldapPort);
	
					LDAPConstraints constraints = conn.getConstraints();
					constraints.setReferralFollowing(false);
					conn.setConstraints(constraints);
	
					log.info("Binding");
	
					conn.bind(ldapVersion, entry.getDN(), password.getPassword()
							.getBytes("UTF8"));
				} finally {
					conn.disconnect();
				}
				return true;
			} catch (UnsupportedEncodingException e) {
			} catch (Exception e) {
				if (useSsl && trustEverything && e.getCause() != null && e.getCause() instanceof IOException) { // SSL Not properly configured
					try {
						log.info("Connecting using plain socket");
						conn = createConnection (false);				
						conn.connect(host, LDAPConnection.DEFAULT_PORT);
		
						LDAPConstraints constraints = conn.getConstraints();
						constraints.setReferralFollowing(false);
						conn.setConstraints(constraints);
		
						log.info("Binding");
		
						conn.bind(ldapVersion, entry.getDN(), password.getPassword()
								.getBytes("UTF8"));
						return true;
					} catch (Exception e2) {
						log.info("Error connecting to " + host + " as user " + user, e2);
					} finally {
						try {
							conn.disconnect();
						} catch (Exception ee) {}
					}
				} else
					log.info("Error connecting to " + host + " as user " + user, e);
			} finally {
				Watchdog.instance().dontDisturb();
			}
		}
		return false;
	}

	private LDAPConnection createConnection() throws NoSuchAlgorithmException, KeyManagementException, KeyStoreException, CertificateException, IOException 
	{
		return createConnection(useSsl);
	}
	
	private LDAPConnection createConnection(boolean useSsl) throws NoSuchAlgorithmException, KeyManagementException, KeyStoreException, CertificateException, IOException 
	{
		LDAPConnection conn;
		if (useSsl)
		{
			log.info("Using SSL");
			
			LDAPSocketFactory ldapSecureSocketFactory = null;


			SSLContext ctx;
			if (trustEverything)
			{
				log.info("Creating a blind connection");
				ctx = SSLContext.getInstance("TLS"); //$NON-NLS-1$
		        ctx.init(new KeyManager[0], new TrustManager[] { new AlwaysTrustManager() }, null);
			}
			else
			{
				log.info("Using Standard SSL");
				ctx = SSLContext.getDefault();
			}
			
			if (debugEnabled)
			{
				DebugLDAPSecureSocketFactory factory = new DebugLDAPSecureSocketFactory(ctx.getSocketFactory());
				if (log != null)
					factory.setLog(log);
				ldapSecureSocketFactory = factory;
				log.info("Using DEBUG wrapper");
			}
			else
				ldapSecureSocketFactory = new LDAPJSSESecureSocketFactory(ctx.getSocketFactory());
			conn = new LDAPConnection(ldapSecureSocketFactory);
		} else  {
			conn = new LDAPConnection();
		}
		
		return (conn);
	}


	public void configureMappings(Collection<ExtensibleObjectMapping> objects)
			throws RemoteException, InternalErrorException {
		this.objectMappings = objects;
		objectTranslator = new ObjectTranslator(getDispatcher(), getServer(),
				objectMappings);
		objectTranslator.setObjectFinder(new ExtensibleObjectFinder() {
			public ExtensibleObject find(ExtensibleObject pattern)
					throws Exception {
				String samAccount = (String) pattern
						.getAttribute(SAM_ACCOUNT_NAME_ATTRIBUTE);
				Watchdog.instance().interruptMe(getDispatcher().getTimeout());
				try {
					if (debugEnabled)
					{
						log.info("Searching for object ");
						debugObject("Pattern", pattern, "  ");
					}
					LDAPEntry entry = searchSamAccount(pattern, samAccount);
					if (entry != null) {
						for (ObjectMapping m : objectMappings) {
							if (m.getSystemObject().equals(
									pattern.getObjectType()))
								return parseEntry(entry, m);
						}
						throw new InternalErrorException("Mapping for object type "+pattern.getObjectType()+" not found");
					}
					return null;
				} finally {
					Watchdog.instance().dontDisturb();
				}
			}

			public Collection<Map<String, Object>> invoke(String verb, String command, Map<String, Object> params)
					throws InternalErrorException {
				try {
					if ("add".equalsIgnoreCase(verb) || "insert".equalsIgnoreCase(verb))
					{
						return addLdapObject (command, params);
					}
					else if ("update".equalsIgnoreCase(verb) || "modify".equalsIgnoreCase(verb))
					{
						return modifyLdapObject (command, params);
					}
					else if ("delete".equalsIgnoreCase(verb) || "remove".equalsIgnoreCase(verb))
					{
						return deleteLdapObject (command, params);
					}
					else if ("select".equalsIgnoreCase(verb) || "query".equalsIgnoreCase(verb))
					{
						return queryLdapObjects (baseDN, command, params);
					}
					else if ("rename".equalsIgnoreCase(verb))
					{
						return renameLdapObjects (command, params);
					}
					else if ("get".equalsIgnoreCase(verb) || "read".equalsIgnoreCase(verb))
					{
						log.info("Getting "+baseDN+" "+command);
						Collection<Map<String, Object>> l = getLdapObjects (baseDN, command, params);
						Collection<Map<String,Object>> l2  = new LinkedList();
						for (Map<String, Object> eo: l)
						{
							Map<String, Object> eo2 = new HashMap<String, Object>();
	    					for (String key: eo.keySet())
	    					{
	    						eo2.put(key, eo.get(key));
	    					}
	    					l2.add(eo2);
						}
						return l2;
					}
					else if ("smb:createFolder".equalsIgnoreCase(verb) ||
							"smb:createDir".equalsIgnoreCase(verb) ||
							"smb:mkdir".equalsIgnoreCase(verb))
					{
						log.info("Creating folder "+command);
						try {
							nasManager.createFolder(command,  nasManager.parseAuthData(params));
						} catch (Exception e) {
							throw new InternalErrorException("Cannot create folder "+command, e);
						}
						return new LinkedList();
					}
					else if ("smb:exist".equalsIgnoreCase(verb))
					{
						Collection<Map<String,Object>> l2  = new LinkedList();
						log.info("Testing folder "+command);
						try {
							boolean v = nasManager.exists(command,  nasManager.parseAuthData(params));
							HashMap<String, Object> m = new HashMap<String,Object>();
							m.put("exist", v);
							l2.add(m);
						} catch (Exception e) {
							throw new InternalErrorException("Cannot create folder "+command, e);
						}
						return l2;
					}
					else if ("smb:getacl".equalsIgnoreCase(verb))
					{
						Collection<Map<String,Object>> l2  = new LinkedList();
						log.info("Getting acl "+command);
						try {
							List<String[]> v = nasManager.getAcl(command,  nasManager.parseAuthData(params));
							for ( String[] vv: v)
							{
								HashMap<String, Object> m = new HashMap<String,Object>();
								m.put("user", vv[0] );
								m.put("permission", vv[1] );
								m.put("flags", vv[2] );
								l2.add(m);
								
							}
						} catch (Exception e) {
							throw new InternalErrorException("Cannot get acl "+command, e);
						}
						return l2;
					}
					else if ("smb:addacl".equalsIgnoreCase(verb))
					{
						Collection<Map<String,Object>> l2  = new LinkedList();
						log.info("Adding acl "+command);
						try {
							String user = (String) params.get("user");
							String permission = (String) params.get("permission");
							String flags = (String) params.get("flags");
							nasManager.addAcl(command, user, permission, flags,  nasManager.parseAuthData(params), params.containsKey("recursive"));
						} catch (Exception e) {
							throw new InternalErrorException("Cannot add acl "+command, e);
						}
						return new LinkedList();
					}
					else if ("smb:removeAclInheritance".equalsIgnoreCase(verb))
					{
						Collection<Map<String,Object>> l2  = new LinkedList();
						log.info("Removing inheritance "+command);
						try {
							nasManager.removeAclInheritance(command,  nasManager.parseAuthData(params));
						} catch (Exception e) {
							throw new InternalErrorException("Cannot add acl "+command, e);
						}
						return new LinkedList();
					}
					else if ("smb:setowner".equalsIgnoreCase(verb))
					{
						Collection<Map<String,Object>> l2  = new LinkedList();
						log.info("Setting owner "+command);
						try {
							String user = (String) params.get("user");
							nasManager.setOwner(command, user,  nasManager.parseAuthData(params));
						} catch (Exception e) {
							throw new InternalErrorException("Cannot add acl "+command, e);
						}
						return new LinkedList();
					}
					else if ("smb:removeacl".equalsIgnoreCase(verb))
					{
						Collection<Map<String,Object>> l2  = new LinkedList();
						log.info("Removing ACL from "+command);
						try {
							String user = (String) params.get("user");
							String permission = (String) params.get("permission");
							String flags = (String) params.get("flags");
							nasManager.removeAcl(command, user, permission, flags,  nasManager.parseAuthData(params));
						} catch (Exception e) {
							throw new InternalErrorException("Cannot set acl of "+command, e);
						}
						return new LinkedList();
					}
					else if ("smb:rm".equalsIgnoreCase(verb))
					{
						Collection<Map<String,Object>> l2  = new LinkedList();
						log.info("Removing "+command);
						try {
							nasManager.rm(command,  nasManager.parseAuthData(params));
						} catch (Exception e) {
							throw new InternalErrorException("Cannot remove "+command, e);
						}
						return new LinkedList();
					}
					else if ("smb:rmdir".equalsIgnoreCase(verb))
					{
						Collection<Map<String,Object>> l2  = new LinkedList();
						log.info("Removing "+command);
						try {
							nasManager.rmFolder(command,  nasManager.parseAuthData(params));
						} catch (Exception e) {
							throw new InternalErrorException("Cannot remove "+command, e);
						}
						return new LinkedList();
					}
					else if ("smb:listShares".equalsIgnoreCase(verb))
					{
						Collection<Map<String,Object>> l2  = new LinkedList();
						log.info("Listing shares "+command);
						try {
							for (String[] shareName: nasManager.listShares(command,  nasManager.parseAuthData(params))) {
								Map<String,Object> m = new HashMap<>();
								m.put("name", shareName[0]);
								m.put("remarks", shareName[1]);
								m.put("type", shareName[2]);
								m.put("server", shareName[3]);
								l2.add(m);
							}
						} catch (Exception e) {
							throw new InternalErrorException("Cannot list shares for server "+command, e);
						}
						return l2;
					}
					else if ("smb:diskSpace".equalsIgnoreCase(verb))
					{
						Collection<Map<String,Object>> l2  = new LinkedList();
						log.info("Calculating disk space "+command);
						try {
							Map<String,Object> m = new HashMap<>();
							m.put("free", nasManager.getFreeSize(command,  nasManager.parseAuthData(params)));
							m.put("size", nasManager.getVolumeSize(command,  nasManager.parseAuthData(params)));
							l2.add(m);
						} catch (Exception e) {
							throw new InternalErrorException("Cannot get disk space for share "+command, e);
						}
						return l2;
					}
					else if (verb.equals("checkPassword"))
					{
						Collection<Map<String, Object>> l = new LinkedList<>();
						Map<String,Object> o = new HashMap<String, Object>();
						l.add(o);
						Account account = getServer().getAccountInfo(command, getDispatcher().getCodi());
						if (account == null)
							o.put("passwordStatus", null);
						else 
						{
							try {
								Password password = getServer().getAccountPassword(command, getDispatcher().getCodi());
								PasswordValidation status = validateUserPassword(account.getName(), password) ? PasswordValidation.PASSWORD_GOOD: PasswordValidation.PASSWORD_WRONG;
								o.put("passwordStatus", status);
							} catch (InternalErrorException e) {
								throw e;
							} catch (Exception e) {
								throw new InternalErrorException ("Error validating password for account "+account.getLoginName(),
										e);
							}
						}
						return l;
					}

					else
					{
						return queryLdapObjects (verb, command, params);
					}
				} finally {
				}

			}

		});
	}

	private Collection<Map<String, Object>> queryLdapObjects(String base, String queryString, Map<String, Object> params) throws InternalErrorException {
		if (params.get("base") != null)
			base = (String) params.get("base");
		String domain = searchDomainForDN(base);
		try {
			LDAPConnection conn = getConnection(domain);
			LDAPPool pool = getPool(domain);
			try
			{
				LinkedList<Map<String, Object>> result = new LinkedList<Map<String,Object>>();
				
				LDAPSearchConstraints constraints = new LDAPSearchConstraints(conn.getConstraints());
				LDAPSearchResults query = conn.search(base,
							LDAPConnection.SCOPE_SUB, queryString, null, false,
							constraints);
				while (query.hasMore()) {
					try {
						LDAPEntry entry = query.next();
						result.add( new LDAPExtensibleObject("unknown", entry, pool) );
					} catch (LDAPReferralException ldapError) {
						if (followReferrals)
							throw ldapError;
					}
				}			
				return result;
			} catch (Exception e) {
				handleException(e, conn);
				throw e;
			} finally {
				returnConnection(domain);
			}
		} catch (Exception e1) {
			throw new InternalErrorException ("Error performing LDAP query", e1);
		}
	}
	
	private Collection<Map<String, Object>> renameLdapObjects(String olddn, Map<String, Object> params) throws InternalErrorException {
		String newdn = (String) params.get("dn");
		
		String domain = searchDomainForDN(olddn);
		try {
			LDAPConnection conn = getConnection(domain);
			LDAPPool pool = getPool(domain);
			try
			{
				LinkedList<Map<String, Object>> result = new LinkedList<Map<String,Object>>();
				
				try {
					LDAPEntry entry = conn.read(olddn);
					if (entry != null) {
						String[] split = splitDN(newdn);
						String parentName =  mergeDN(split, 1);
						conn.rename(entry.getDN(), split[0], parentName, true);
					}
				} 
				catch (LDAPReferralException e)
				{
					// Ignore
				}
				catch (LDAPException e2)
				{
					handleException(e2, conn);
					if (e2.getResultCode() == LDAPException.NO_SUCH_OBJECT) {
						// Ignore
					} else {
						log.debug("LDAP Exception: "+e2.toString());
						log.debug("ERROR MESSAGE: "+e2.getLDAPErrorMessage());
						log.debug("LOCALIZED MESSAGE: "+e2.getLocalizedMessage());
						throw e2;
					}
				}
				return result;
			} finally {
				returnConnection(domain);
			}
		} catch (Exception e1) {
			throw new InternalErrorException ("Error performing LDAP query", e1);
		}
	}

	private Collection<Map<String, Object>> getLdapObjects(String base, String queryString, Map<String, Object> params) throws InternalErrorException {
		String domain = searchDomainForDN(queryString);
		try {
			LDAPConnection conn = getConnection(domain);
			LDAPPool pool = getPool(domain);
			try
			{
				LinkedList<Map<String, Object>> result = new LinkedList<Map<String,Object>>();
				
				try {
					LDAPEntry entry = conn.read(queryString);
					result.add( new LDAPExtensibleObject("unknown", entry, pool) );
				} 
				catch (LDAPReferralException e)
				{
					// Ignore
				}
				catch (LDAPException e2)
				{
					handleException(e2, conn);
					if (e2.getResultCode() == LDAPException.NO_SUCH_OBJECT) {
						// Ignore
					} else {
						log.debug("LDAP Exception: "+e2.toString());
						log.debug("ERROR MESSAGE: "+e2.getLDAPErrorMessage());
						log.debug("LOCALIZED MESSAGE: "+e2.getLocalizedMessage());
						throw e2;
					}
				}
				return result;
			} finally {
				returnConnection(domain);
			}
		} catch (Exception e1) {
			throw new InternalErrorException ("Error performing LDAP query", e1);
		}
	}
	
	private Collection<Map<String, Object>> deleteLdapObject(String dn, Map<String, Object> params) throws InternalErrorException {
		String domain = searchDomainForDN(dn);
		try {
			LDAPConnection conn = getConnection(domain);
			try
			{
				LDAPConstraints c = conn.getConstraints();
				LDAPControl recursivelyDelete = new LDAPControl ("1.2.840.113556.1.4.805", true, null);
				LDAPControl recursivelyDeleteEx = new LDAPControl ("1.2.840.113556.1.4.2204", true, null);
				c.setControls(new LDAPControl[] {
					recursivelyDelete,
					recursivelyDeleteEx
				});
				conn.delete(dn);
				return null;
			} catch (Exception e) {
				handleException(e, conn);
				throw e;
			} finally {
				returnConnection(domain);
			}
		} catch (Exception e1) {
			throw new InternalErrorException ("Error performing LDAP query", e1);
		}
	}
	
	private Collection<Map<String, Object>> modifyLdapObject(String dn, Map<String, Object> params) throws InternalErrorException {
		String domain = searchDomainForDN(dn);
		try {
			LDAPConnection conn = getConnection(domain);
			try
			{
				LDAPEntry entry = conn.read(dn);
				List<LDAPModification> mods = new LinkedList<LDAPModification>();
				for (String param: params.keySet())
				{
					if (!param.equals("dn"))
					{
						Object value = params.get(param);
						LDAPAttribute previous = entry.getAttribute(param);
						if (value == null
								&& previous != null) {
							mods.add(new LDAPModification(
									LDAPModification.DELETE,
									new LDAPAttribute(param)));
						} else if (value != null
								&& previous == null) {
							if (value instanceof byte[]) {
								mods.add(new LDAPModification(
										LDAPModification.ADD,
										new LDAPAttribute(param,
												(byte[]) value)));
							} else  if (value instanceof String[]) {
								mods.add(new LDAPModification(
										LDAPModification.ADD,
										new LDAPAttribute(param, (String[])value)));
							} else {
								mods.add(new LDAPModification(
										LDAPModification.ADD,
										new LDAPAttribute(param, value.toString())));
							}
						} else if ((value != null)
								&& (previous != null)) {
							if (value instanceof byte[]) {
								mods.add(new LDAPModification(
										LDAPModification.REPLACE,
										new LDAPAttribute(param,
												(byte[]) value)));
							} else  if (value instanceof String[]) {
								mods.add(new LDAPModification(
										LDAPModification.REPLACE,
										new LDAPAttribute(param, (String[])value)));
							} else {
								mods.add(new LDAPModification(
										LDAPModification.REPLACE,
										new LDAPAttribute(param, value.toString())));
							}
						}
					}
				}
				if (debugEnabled)
					debugModifications("Modifying object ",
						dn,
						mods.toArray(new LDAPModification[0]));
				conn.modify(dn, mods.toArray(new LDAPModification[0]));
				return null;
			} catch (Exception e) {
				handleException(e, conn);
				throw e;
			} finally {
				returnConnection(domain);
			}
		} catch (Exception e1) {
			throw new InternalErrorException ("Error modifying LDAP query", e1);
		}
	}
	
	protected Collection<Map<String, Object>> addLdapObject(String dn, Map<String, Object> params) throws InternalErrorException {
		String domain = searchDomainForDN(dn);
		try {
			LDAPConnection conn = getConnection(domain);
			try
			{
				LDAPAttributeSet attributes = new LDAPAttributeSet();
				for (String param: params.keySet())
				{
					Object value = params.get(param);
					if (value == null)
					{
						// Nothing to do
					}
					else if (value instanceof byte[]) 
					{
						attributes.add(
								new LDAPAttribute(param,
										(byte[]) value));
					} else  if (value instanceof String[]) {
						attributes.add(new LDAPAttribute(param, (String[])value));
					} else {
						attributes.add(new LDAPAttribute(param, value.toString()));
					}
				}
				if (debugEnabled)
					debugEntry("Creating object", dn, attributes);
				conn.add( new LDAPEntry(dn, attributes));
				return null;
			} catch (Exception e) {
				handleException(e, conn);
				throw e;
			} finally {
				returnConnection(domain);
			}
		} catch (Exception e1) {
			throw new InternalErrorException ("Error modifying LDAP query", e1);
		}
		
	}


	AttributeMapping findAttribute(ExtensibleObjectMapping objectMapping,
			String attribute) {
		for (AttributeMapping attMapping : objectMapping.getAttributes()) {
			if (attMapping.getSystemAttribute().equals(attribute)
					&& (attMapping.getDirection().equals(
							AttributeDirection.OUTPUT) || attMapping
							.getDirection().equals(
									AttributeDirection.INPUTOUTPUT))) {
				return attMapping;
			}
		}
		return null;
	}

	LinkedList<String> getSoffidAccounts(SoffidObjectType type)
			throws Exception {
		LinkedList<String> accounts = new LinkedList<String>();
		for (String domain: domainHost.keySet())
		{
			String base = domain;
			LDAPConnection conn = getConnection(domain);
			try {
	
				ExtensibleObject dummySoffidObj = new ExtensibleObject();
				dummySoffidObj.setObjectType(type.getValue());
	
				for (ExtensibleObjectMapping mapping : objectMappings) {
					if (mapping.getSoffidObject().equals(type)) {
						ExtensibleObject dummySystemObject = objectTranslator
								.generateObject(dummySoffidObj, mapping, true);
	
						StringBuffer sb = new StringBuffer();
						sb.append("(&");
						boolean any = false;
						if (dummySystemObject == null)
						{
							sb.append("(objectClass=user)");
						}
						else
						{
							for (String att : dummySystemObject.getAttributes()) {
								String value = vom.toSingleString(dummySystemObject
										.getAttribute(att));
								if ((value != null) && !"dn".equals(att)) {
									if (BASE_DN.equals(att))
									{
										
									}
									else if (RELATIVE_DN.equals(att))
									{
										
									}
									else
									{
										sb.append("(").append(att).append("=")
												.append(value).append(")");
										any = true;
									}
								}
							}
						}
						if (mapping.getProperties().containsKey("searchBase"))
							base =  mapping.getProperties().get("searchBase")+","+base;
						sb.append("(!(objectClass=computer)))");
						if (any && base != null) {
							LDAPPagedResultsControl pageResult = new LDAPPagedResultsControl(
									conn.getSearchConstraints().getMaxResults(),
									false);
	
							do {
								LDAPSearchConstraints constraints = new LDAPSearchConstraints(conn.getSearchConstraints());
								constraints.setControls(pageResult);
								constraints.setServerTimeLimit( 
										getDispatcher().getLongTimeout() == null ? 0: 
											getDispatcher().getLongTimeout().intValue());
	
								if (debugEnabled)
									log.info("Looking for objects: LDAP QUERY="
											+ sb.toString() + " on " + base);
								LDAPSearchResults search = conn.search(base,
										LDAPConnection.SCOPE_SUB, sb.toString(),
										null, false, constraints);
								while (search.hasMore()) {
									try {
										LDAPEntry entry = search.next();
										
										accounts.add(generateAccountName(entry, mapping, "accountName"));
									} catch (LDAPReferralException ldapError) {
										if (followReferrals)
											throw ldapError;
									} catch (LDAPException e) {
										handleException(e, conn);
										if (e.getResultCode() == LDAPException.NO_SUCH_OBJECT) {
											// Ignore
										} else {
											log.debug("LDAP Exception: "+e.toString());
											log.debug("ERROR MESSAGE: "+e.getLDAPErrorMessage());
											log.debug("LOCALIZED MESSAGE: "+e.getLocalizedMessage());
											throw e;
										}
									}
								}
	
								LDAPControl responseControls[] = search
										.getResponseControls();
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
				}
			} catch (LDAPException e) {
				handleException(e, conn);
				throw e;
			} finally {
				returnConnection(domain);
			}
		}
		return accounts;
	}

	public String generateAccountName(LDAPEntry entry, ExtensibleObjectMapping mapping, String attName) throws InternalErrorException {
		
		String accountName = null;
		if (mapping != null)
			accountName = 
				(String) objectTranslator
					.parseInputAttribute(attName, 
						new LDAPExtensibleObject(mapping.getSystemObject(), entry, getEntryPool(entry)),
						mapping);

		if (accountName == null)
		{
			LDAPAttribute att = entry.getAttribute(SAM_ACCOUNT_NAME_ATTRIBUTE);
			if (att == null)
				return null;
			accountName = att.getStringValue().toLowerCase();
			if (multiDomain)
			{
				String entryDn = entry.getDN().toLowerCase();
				String ntDomain = searchNTDomainForDN(entryDn);
				if (ntDomain == null)
				{
					log.warn("DN: "+entryDn);
					throw new InternalErrorException("Unable to guess domain for "+entryDn);
				}
				accountName = ntDomain+"\\"+accountName;
			}
		}
		return accountName;
	}


	protected LDAPPool getEntryPool(LDAPEntry entry) throws InternalErrorException {
		return getPool(getDomain(entry));
	}

	protected String getDomain(LDAPEntry entry) throws InternalErrorException
	{
		String entryDn = entry.getDN().toLowerCase();
		String domain = searchDomainForDN(entry.getDN());
		if (domain != null)
			return domain;
		
		log.warn("DN: "+entryDn);
		for (String d: domainHost.keySet())
		{
			log.warn("Base: "+d);
		}
		throw new InternalErrorException("Unable to guess domain for "+entryDn);
	}

	private String removeIncompleteComponentsFromBase(String base) {
		if (base == null)
			return null;
		else if (base.endsWith("=")) {
			base = base.substring(0, base.lastIndexOf(",")).trim();
		}
		if (base.endsWith(","))
			base = base.substring(0, base.length() - 1);
		return base;
	}

	public List<String> getAccountsList() throws RemoteException,
			InternalErrorException {
		Set<String> accounts = new HashSet<String>();
		Watchdog.instance().interruptMe(getDispatcher().getLongTimeout());
		try {
			accounts.addAll(getSoffidAccounts(SoffidObjectType.OBJECT_ACCOUNT));
			if (accounts.isEmpty())
				accounts.addAll(getSoffidAccounts(SoffidObjectType.OBJECT_USER));
		} catch (Exception e) {
			throw new InternalErrorException("Error getting accounts list", e);
		} finally {
			Watchdog.instance().dontDisturb();
		}
		return new LinkedList<String>(accounts);
	}

	public ExtensibleObject parseEntry(LDAPEntry entry, ObjectMapping mapping) throws InternalErrorException {
		return new LDAPExtensibleObject(mapping.getSystemObject(), entry, getEntryPool(entry));
	}

	public Usuari getUserInfo(String userAccount) throws RemoteException,
			InternalErrorException {
		ExtensibleObject eo;
		Watchdog.instance().interruptMe(getDispatcher().getTimeout());
		try {
			eo = findExtensibleUser(userAccount);
		} catch (InternalErrorException e) {
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException(e.getMessage());
		} finally {
			Watchdog.instance().dontDisturb();
		}

		if (eo == null)
			return null;
		ExtensibleObjects parsed = objectTranslator.parseInputObjects(eo);
		for (ExtensibleObject peo : parsed.getObjects()) {
			Usuari usuari = vom.parseUsuari(peo);
			if (usuari != null)
				return usuari;
			Account account = vom.parseAccount(peo);
			if (account != null) {
				usuari = new Usuari();
				usuari.setCodi(userAccount);
				usuari.setFullName(account.getDescription());
				usuari.setPrimerLlinatge(account.getDescription());
				usuari.setNom(account.getName());
				return usuari;
			}
		}
		return null;
	}

	private ExtensibleObject findExtensibleUser(String userAccount)
			throws Exception {
		return findUserByExample(userAccount);
	}

	private ExtensibleObject findUserByExample(String userAccount)
			throws Exception {
		ExtensibleObject account = new ExtensibleObject();
		account.setObjectType(SoffidObjectType.OBJECT_ACCOUNT.getValue());
		account.setAttribute("accountName", userAccount);
		// For each suitable mappping
		for (ExtensibleObjectMapping objectMapping : objectMappings) {
			if (objectMapping.getSoffidObject().getValue()
					.equals(account.getObjectType())) {
				// Generate system objects from source user
				ExtensibleObject systemObject = objectTranslator
						.generateObject(account, objectMapping, true);

				LDAPEntry result = searchSamAccount(systemObject, userAccount);
				if (result != null) {
					return parseEntry(result, objectMapping);
				}
			}
		}
		return null;
	}

	public List<String> getRolesList() throws RemoteException,
			InternalErrorException {
		Set<String> roles = new HashSet<String>();
		Watchdog.instance().interruptMe(getDispatcher().getLongTimeout());
		try {
			roles.addAll(getSoffidRoles(SoffidObjectType.OBJECT_GROUP));
			roles.addAll(getSoffidRoles(SoffidObjectType.OBJECT_ROLE));
		} catch (LDAPException e) {
			throw new InternalErrorException("Error getting accounts list", e);
		} catch (Exception e) {
			throw new InternalErrorException("Error getting accounts list", e);
		} finally {
			Watchdog.instance().dontDisturb();
		}
		return new LinkedList<String>(roles);
	}

	/**
	 * @param objectGroup
	 * @return
	 * @throws Exception
	 */
	LinkedList<String> getSoffidRoles(SoffidObjectType objectGroup)
			throws Exception {

		LinkedList<String> roles = new LinkedList<String>();
		
		for (String domain: domainHost.keySet())
		{
			String base = domain;
			LDAPConnection conn = getConnection(domain);
			try {
				ExtensibleObject dummySoffidObj = new ExtensibleObject();
				dummySoffidObj.setObjectType(objectGroup.getValue());
	
				for (ExtensibleObjectMapping mapping : objectMappings) {
					if (mapping.getSoffidObject().equals(objectGroup)) {
						ExtensibleObject dummySystemObject = objectTranslator
								.generateObject(dummySoffidObj, mapping, true);
	
						StringBuffer sb = new StringBuffer();
						sb.append("(&");
						boolean any = false;
						for (String att : dummySystemObject.getAttributes()) {
							String value = vom.toSingleString(dummySystemObject
									.getAttribute(att));
							if (value != null)
							{
								if (BASE_DN.equals(att))
								{
									
								}
								else if (RELATIVE_DN.equals(att))
								{
									
								}
								else if (!"dn".equals(att)
									&& !BASE_DN.equals(att)
									&& !RELATIVE_DN.equals(att)) {
									sb.append("(").append(att).append("=")
											.append(escapeLDAPSearchFilter(value))
											.append(")");
									any = true;
								}
							}
						}
						sb.append(")");
						if (any && base != null) {
							if (mapping.getProperties().containsKey("searchBase"))
								base =  mapping.getProperties().get("searchBase")+","+base;
							LDAPPagedResultsControl pageResult = new LDAPPagedResultsControl(
									conn.getSearchConstraints().getMaxResults(),
									false);
	
							do {
								LDAPSearchConstraints constraints = new LDAPSearchConstraints(conn.getConstraints());
								constraints.setControls(pageResult);
								constraints.setServerTimeLimit( 
										getDispatcher().getLongTimeout() == null ? 0: 
											getDispatcher().getLongTimeout().intValue());
	
								if (debugEnabled)
									log.info("Looking for role objects: LDAP QUERY="
											+ sb.toString() + " on " + base);
								LDAPSearchResults search = conn.search(base,
										LDAPConnection.SCOPE_SUB, sb.toString(),
										null, false, constraints);
								while (search.hasMore()) {
									try {
										LDAPEntry entry = search.next();
										String accountName = generateAccountName(entry, mapping, "name"); 
										roles.add(accountName);
										if (debugEnabled)
										{
											log.info("Got "+accountName+" => "+entry.getDN());
										}
									} catch (LDAPReferralException ldapError) {
										if (followReferrals)
											throw ldapError;
									}
								}
	
								LDAPControl responseControls[] = search
										.getResponseControls();
								pageResult.setCookie(null); 
	
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
				}
			} catch (LDAPException e) {
				handleException(e, conn);
				throw e;
			} finally {
				returnConnection(domain);
			}
		}
		return roles;
	}
	
	private HashMap<String, Rol> rolesCache = new HashMap<String, Rol>();
	
	public Rol getRoleFullInfo(String roleName) throws RemoteException,
			InternalErrorException {
		ExtensibleObject rolObject = new ExtensibleObject();
		rolObject.setObjectType(SoffidObjectType.OBJECT_ROLE.getValue());
		rolObject.setAttribute("name", roleName);
		rolObject.setAttribute("system", getDispatcher().getCodi());

		if (debugEnabled)
			log.info("Looking for role "+roleName);
		// Generate a dummy object to perform query
		ExtensibleObjects systemObjects = objectTranslator
				.generateObjects(rolObject);
		for (ExtensibleObject systemObject : systemObjects.getObjects()) {
			LDAPEntry entry = null;
			Watchdog.instance().interruptMe(getDispatcher().getTimeout());
			try {
				entry = searchSamAccount(systemObject, roleName);
			} catch (LDAPException e) {
				throw new InternalErrorException(e.getMessage(), e);
			} catch (InternalErrorException e) {
				throw e;
			} catch (Exception e) {
				throw new InternalErrorException(e.getMessage(), e);
			} finally {
				Watchdog.instance().dontDisturb();
			}
			if (entry != null) {
				for (ExtensibleObjectMapping objectMapping : objectMappings) {
					if (objectMapping.getSoffidObject().getValue()
							.equals(rolObject.getObjectType())) {
						ExtensibleObject eo = parseEntry(entry, objectMapping);
						ExtensibleObject parsed = objectTranslator
								.parseInputObject(eo, objectMapping);
						if (parsed != null) {
							Rol rol = vom.parseRol(parsed);
							if (rol != null) {
								if (rol.getDescripcio() == null)
									rol.setDescripcio(entry.getAttribute("CN")
											.getStringValue());
								rol.setNom(roleName);
								
								List<RolGrant> l = new LinkedList<>();
								LDAPAttribute memberofattr = entry.getAttribute("memberOf");
								String soffidGroups[] = ((memberofattr == null) ? new String[] {}
										: memberofattr.getStringValueArray());
								if (useNestedGroups() ) {
									for (int i = 0; i < soffidGroups.length; i++) {
										LDAPEntry groupEntry;
										try {
											groupEntry = searchEntry(soffidGroups[i]);
										} catch (Exception e) {
											throw new InternalErrorException("Error fetching group "+soffidGroups[i], e);
										}
										String accountName = generateAccountName(groupEntry, null, "name"); 
										RolGrant rg = new RolGrant();
										rg.setDispatcher(getCodi());
										rg.setOwnerRolName(roleName);
										rg.setOwnerDispatcher(getCodi());
										rg.setRolName(accountName);
										l.add(rg);
									}	
									rol.setOwnedRoles(l);
								} else {
									rol.setOwnedRoles(null);
								}
								rol.setOwnerRoles(null);
								
								rolesCache.put(entry.getDN().toLowerCase(), rol);
								return rol;
							}
						}
					}
				}
			}
		}
		return null;
	}

	Boolean compatibleSyncserver = null;
	private boolean useNestedGroups() {
		try {
			boolean flat = ! "false".equals(extendedAttributes.get("flatGroups"));

			if (flat) return false;
			
			if (compatibleSyncserver == null) {
				Properties props = new Properties();
				props.load(getClass().getResourceAsStream("/META-INF/maven/com.soffid.iam.sync/syncserver/pom.properties"));
				String version = props.getProperty("version");
				String[] split = version.split("[.-]");
				int number = Integer.parseInt(split[0]);
				if (number > 3) return (compatibleSyncserver = Boolean.TRUE).booleanValue();
				if (number < 3) return (compatibleSyncserver = Boolean.FALSE).booleanValue();
				number = Integer.parseInt(split[1]);
				if (number > 3) return (compatibleSyncserver = Boolean.TRUE).booleanValue();
				if (number < 3) return (compatibleSyncserver = Boolean.FALSE).booleanValue();
				number = Integer.parseInt(split[2]);
				if (number >= 28) return (compatibleSyncserver = Boolean.TRUE).booleanValue();
				return (compatibleSyncserver = Boolean.FALSE).booleanValue();
			}
			else
				return compatibleSyncserver.booleanValue();
		} catch (Exception e) {
			return false;
		}
		
	}


	public List<Rol> getAccountRoles(String userAccount)
			throws RemoteException, InternalErrorException {
		Rol userRole; // User role
		LinkedList<Rol> rolesList = new LinkedList<Rol>(); // User roles
		LDAPEntry userEntry; // User LDAP entry
		Watchdog.instance().interruptMe(getDispatcher().getTimeout());
		try {
			ExtensibleObject eo = findExtensibleUser(userAccount);
			LDAPAttribute memberofattr; // User LDAP groups
			String userGroups[]; // User group array

			Object memberofattr1 = eo.getAttribute("dn");
			userEntry = searchEntry(memberofattr1.toString());
			memberofattr = userEntry.getAttribute("memberOf");
			userGroups = (memberofattr == null ? new String[] {} : memberofattr
					.getStringValueArray());

			// Process the user groups
			for (int i = 0; i < userGroups.length; i++) {
				Rol r = rolesCache.get(userGroups[i].toLowerCase());
				if (r != null) {
					rolesList.add(r);
					log.info("User {} belongs to [{}] (cached)", userAccount,
							r.getNom());
				}
				else
				{
					LDAPEntry roleEntry = searchEntry(userGroups[i], new String [] {"CN", "sAMAccountName"});
					if (roleEntry != null) {
						for (ExtensibleObjectMapping objectMapping : objectMappings) {
							if (objectMapping.getSoffidObject().equals(SoffidObjectType.OBJECT_ROLE)) {
								Rol rol = new Rol();
								if (rol.getDescripcio() == null)
									rol.setDescripcio(roleEntry.getAttribute("CN").getStringValue());
								rol.setNom( generateAccountName(roleEntry, objectMapping, "name"));
								log.info("User {} belongs to [{}]", userAccount,
												rol.getNom());
								rolesList.add(rol);
							}
						}
					}
				}

			}
		} catch (LDAPException e) {
			throw new InternalErrorException(e.getMessage());
		} catch (InternalErrorException e) {
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException(e.getMessage(), e);
		} finally {
			Watchdog.instance().dontDisturb();
		}

		return rolesList;
	}

	public void updateUser(String userName, Usuari userData)
			throws RemoteException, InternalErrorException {
		Account account = getServer().getAccountInfo(userName, getCodi());
		if (isDebug())
			log.info("BEGIN Generating AD user object");
		UserExtensibleObject source = new UserExtensibleObject(account,
				userData, getServer());
		ExtensibleObjects objects = objectTranslator.generateObjects(source);

		if (isDebug())
			log.info("END");
		Watchdog.instance().interruptMe(getDispatcher().getTimeout());
		try {
			updateObjects(getAccountName(account), userName, objects, source, null, !account.isDisabled());
			for (ExtensibleObject object : objects.getObjects()) {
				if ("user".equalsIgnoreCase((String) object.getAttribute("objectClass"))) {
					updateUserStatus(userName, object, !account.isDisabled(), new UserExtensibleObject(account, userData, getServer()), null);
					updateUserGroups(userName, object, !account.isDisabled(), null /*always apply */);
				}
			}
		} catch (LDAPException e) {
			throw new InternalErrorException("Error updating user", e);
		} catch (UnknownUserException e) {
			throw new InternalErrorException("Error updating user", e);
		} catch (UnknownRoleException e) {
			throw new InternalErrorException("Error updating user", e);
		} catch (InternalErrorException e) {
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException("Error updating user", e);
		} finally {
			Watchdog.instance().dontDisturb();
		}
	}

	/**
	 * @param userData
	 * @param object
	 * @param soffidObject 
	 * @param changes 
	 * @throws Exception
	 */
	private void updateUserStatus(String userName, ExtensibleObject object, boolean enable, ExtensibleObject soffidObject, List<String[]> changes)
			throws Exception {
		if (isDebug())
			log.info("BEGIN Setting user status (userAccountControl");

		LDAPEntry entry = searchSamAccount(object, userName);

		if (entry != null) {
			LDAPModification modif = null;

			// Update 'userAccountControl' attribute
			int status = 0;
			LDAPAttribute att = entry.getAttribute(USER_ACCOUNT_CONTROL);

			if (att != null)
				status = Integer.decode(att.getStringValue()).intValue();
			int oldStatus = status;

			log.info("Current user status: "+status);
			// Remove 'disable'
			if (enable)
			{
				status = status & (~ADS_UF_ACCOUNTDISABLE);
				// Remove 'lockout'
				status = status & (~ADS_UF_LOCKOUT);
			} else {
				status = status | (ADS_UF_ACCOUNTDISABLE);
			}
			// Remove flag to never password expires
			// status = status & (~ADS_UF_DONT_EXPIRE_PASSWD);
			// Enable normal account status
			status = status | ADS_UF_NORMAL_ACCOUNT;
			
			if (status != oldStatus && changes != null)
			{
				changes.add(new String [] { "Update "+USER_ACCOUNT_CONTROL, Integer.toString(oldStatus), Integer.toString(status)});
				if ((oldStatus & ADS_UF_ACCOUNTDISABLE) == 0 && (status & ADS_UF_ACCOUNTDISABLE) != 0 )
					changes.add(new String [] { "Disable account"});
				if ((oldStatus & ADS_UF_ACCOUNTDISABLE) != 0 && (status & ADS_UF_ACCOUNTDISABLE) == 0 )
					changes.add(new String [] { "Enable account"});
				if ((oldStatus & ADS_UF_LOCKOUT) != 0 && (status & ADS_UF_LOCKOUT) == 0 )
					changes.add(new String [] { "Unlock account"});
			}
			else if (status != oldStatus)
			{
				object.setAttribute(USER_ACCOUNT_CONTROL, Integer.toString(status));
				
				modif = new LDAPModification(LDAPModification.REPLACE,
						new LDAPAttribute(USER_ACCOUNT_CONTROL,
								Integer.toString(status)));
				debugModifications("Updating user data ", entry.getDN(),
						new LDAPModification[] { modif });
				String domain = searchDomainForDN(entry.getDN());
				LDAPConnection conn = getConnection(domain);
				try {
					conn.modify(entry.getDN(), modif);
				} catch (LDAPException e) {
					log.info("Error updating user account control "+e.toString());
					if (e.getResultCode() == LDAPException.UNWILLING_TO_PERFORM && enable && entry.getAttribute("unicodePwd") == null)
					{
						log.info("Error does not have password");
						Password password = getServer().getOrGenerateUserPassword(userName, getDispatcher().getCodi());
					
						if (conn.isTLS())
						{
							log.info("Setting password via LDAP ");
							byte b[] = encodePassword(password);
							LDAPModification modif2 = new LDAPModification(LDAPModification.ADD, new LDAPAttribute("unicodePwd", b));
							LDAPModification[] mods = new LDAPModification[] { modif2, modif };
							debugModifications("Updating user data ", entry.getDN(), mods);
							conn.modify(entry.getDN(), mods);
						} else {
							log.info("Setting password via SAM ");
							updateSamPassword(domain, userName, password, true);
							conn.modify(entry.getDN(), modif);
						}
					}
					else
					{
						handleException(e, conn);
						throw e;
					}
				} finally {
					returnConnection(domain);
				}
			}
			if (enable && 
				entry.getAttribute("lockoutTime") != null &&
				!entry.getAttribute("lockoutTime").getStringValue().equals("0"))
			{
				if (changes != null)
					changes.add( new String[] {"Unlock account", entry.getAttribute("lockoutTime").getStringValue(),""});
				else {
					String domain = searchDomainForDN(entry.getDN());
					LDAPConnection conn = getConnection(domain);
					try {
						conn.modify(entry.getDN(), new LDAPModification[] {
								new LDAPModification(LDAPModification.REPLACE,
										new LDAPAttribute("lockoutTime", "0"))
						});
					} finally {
						returnConnection(domain);
					}
				}
			}
		}
		if (isDebug())
			log.info("END");
	}

	/**
	 * @param userName
	 * @param changes 
	 * @param userData
	 * @param searchSamAccount
	 * @throws Exception
	 * @throws UnknownGroupException
	 */
	private void updateUserGroups(String userName, ExtensibleObject object, boolean enabled, List<String[]> changes)
			throws Exception {
		// Aquí llegamos en usuarios nuevos y existentes ACTIVOS
		// Gestionamos la membresía del usuario a roles y grupos
		// en el atributo memberOf del usuario lo tenemos
		if (isDebug())
			log.info("BEGIN Setting group membership");
		LDAPEntry userEntry = searchSamAccount(object, userName);
		if (userEntry == null) {
			if (isDebug())
				log.info("END");
			return;
		}
		
		LDAPAttribute memberofattr = userEntry.getAttribute("memberOf");
		String dispatcher = getCodi();
		String soffidGroups[] = ((memberofattr == null) ? new String[] {}
				: memberofattr.getStringValueArray());
		HashMap<String, String> h_soffidGroups = new HashMap<String, String>(); // Soffid
																				// groups

		for (int i = 0; i < soffidGroups.length; i++) {
			log.info("Reading group "+soffidGroups[i]);
			LDAPEntry groupEntry = null;
			try {
				groupEntry = searchEntry(soffidGroups[i]);
			} catch (Exception e) {
				log.info("Cannot read group "+soffidGroups[i]);
			}
			if (groupEntry != null) {
				String accountName = generateAccountName(groupEntry, null, "name"); 
				h_soffidGroups.put(accountName, groupEntry.getDN());
			}
		}

		// roles seycon: rolesUsuario - grupos seycon: grupsUsuari
		// Get roles and groups of users
		HashSet<String> groups = new HashSet<String>();

		Exception lastException = null;
		if (enabled)
		{
			for (RolGrant grant : getServer().getAccountRoles(userName, dispatcher)) {
				if (!groups.contains(grant.getRolName())) {
					if (!useNestedGroups() || grant.getOwnerRol() == null || !grant.getOwnerDispatcher().equals(getCodi()))
						groups.add(grant.getRolName());
				}
			}
			for (Grup grup : getServer().getUserGroups(userName, dispatcher)) {
				if (!groups.contains(grup.getCodi()))
					groups.add(grup.getCodi());
			}
			for (Iterator<String> it = groups.iterator(); it.hasNext();) {
				String groupCode = it.next();
				if (!h_soffidGroups.containsKey(groupCode.toLowerCase()))
				{
					if (isDebug())
						log.info("BEGIN Adding {} to [{}]", userName, groupCode);
					try {
						if (changes != null)
						{
							changes.add(new String[] {"Grant group", groupCode});
						}
						else
						{
							addGroupMember(groupCode, userName, userEntry);							
						}
					} catch (Exception e) {
						lastException = e;
						log.warn("Error adding group membership", e);
					} finally {
						if (isDebug())
							log.info("END");
					}
				}
				else {
					if (isDebug())
						log.info("Keeping membership to {}", groupCode, null);
					h_soffidGroups.remove(groupCode.toLowerCase());
				}
			}
		}

		// Esborram dels grups excedents
		for (Iterator it = h_soffidGroups.entrySet().iterator(); it.hasNext();) {
			Map.Entry<String, String> entry = (Map.Entry<String, String>) it
					.next();
			if (isDebug())
				log.info("BEGIN Removing {} from {}", userName, entry.getValue());
			try {
				if (changes != null)
				{
					changes.add(new String[] {"Revoke group", entry.getValue()});
				}
				else
				{
					removeGroupMember(entry.getValue(), userName, userEntry);
				}
			} catch (Exception e) {
				lastException = e;
				log.warn("Error removing group membership", e);
			} finally {
				if (isDebug())
					log.info("END");
			}
		}
		if (isDebug())
			log.info("END");
		if (lastException != null)
			throw lastException;
	}

	private void updateRoleGroups(Rol role, ExtensibleObject object, boolean enabled, List<String[]> changes)
			throws Exception {
		// Aquí llegamos en usuarios nuevos y existentes ACTIVOS
		// Gestionamos la membresía del usuario a roles y grupos
		// en el atributo memberOf del usuario lo tenemos
		if (isDebug())
			log.info("BEGIN Setting group membership");
		String roleName = role.getNom();
		LDAPEntry userEntry = searchSamAccount(object, roleName);
		if (userEntry == null) {
			if (isDebug())
				log.info("END");
			return;
		}
		
		LDAPAttribute memberofattr = userEntry.getAttribute("memberOf");
		String dispatcher = getCodi();
		String soffidGroups[] = ((memberofattr == null) ? new String[] {}
				: memberofattr.getStringValueArray());
		HashMap<String, String> h_soffidGroups = new HashMap<String, String>(); // Soffid
																				// groups

		for (int i = 0; i < soffidGroups.length; i++) {
			LDAPEntry groupEntry = searchEntry(soffidGroups[i]);
			String accountName = generateAccountName(groupEntry, null, "name"); 
			h_soffidGroups.put(accountName, groupEntry.getDN());
		}

		// roles seycon: rolesUsuario - grupos seycon: grupsUsuari
		// Get roles and groups of users
		HashSet<String> groups = new HashSet<String>();

		Exception lastException = null;
		if (enabled)
		{
			Rol ri = getServer().getRoleInfo(roleName, getCodi());
			for (RolGrant grant : ri.getOwnedRoles()) {
				if (!groups.contains(grant.getRolName())) {
					groups.add(grant.getRolName());
				}
			}
			for (Iterator<String> it = groups.iterator(); it.hasNext();) {
				String groupCode = it.next();
				if (!h_soffidGroups.containsKey(groupCode.toLowerCase()))
				{
					if (isDebug())
						log.info("BEGIN Adding {} to [{}]", roleName, groupCode);
					try {
						if (changes != null)
						{
							changes.add(new String[] {"Grant group", groupCode});
						}
						else
						{
							addGroupMember(groupCode, roleName, userEntry);							
						}
					} catch (Exception e) {
						lastException = e;
						log.warn("Error adding group membership", e);
					} finally {
						if (isDebug())
							log.info("END");
					}
				}
				else {
					if (isDebug())
						log.info("Keeping membership to {}", groupCode, null);
					h_soffidGroups.remove(groupCode.toLowerCase());
				}
			}
		}

		// Esborram dels grups excedents
		for (Iterator it = h_soffidGroups.entrySet().iterator(); it.hasNext();) {
			Map.Entry<String, String> entry = (Map.Entry<String, String>) it
					.next();
			if (isDebug())
				log.info("BEGIN Removing {} from {}", roleName, entry.getValue());
			try {
				if (changes != null)
				{
					changes.add(new String[] {"Revoke group", entry.getValue()});
				}
				else
				{
					removeGroupMember(entry.getValue(), roleName, userEntry);
				}
			} catch (Exception e) {
				lastException = e;
				log.warn("Error removing group membership", e);
			} finally {
				if (isDebug())
					log.info("END");
			}
		}
		if (isDebug())
			log.info("END");
		if (lastException != null)
			throw lastException;
	}

	/**
	 * @param grup
	 * @param userName
	 * @param userEntry
	 * @throws Exception
	 * @throws UnknownGroupException
	 */
	private void removeGroupMember(String groupDN, String userName,
			LDAPEntry userEntry) throws Exception {
		log.info("Removing user {} from group {}", userName, groupDN);
		String domain = searchDomainForDN(groupDN);
		LDAPConnection c = getConnection(domain);
		try {
			LDAPEntry groupEntry = searchEntry(groupDN);

			// No existing group
			if (groupEntry == null) {
				return;
			} else {
				if (preDeleteTrigger(
						generateAccountName(groupEntry, null, "name"),
						userName, groupEntry,
						userEntry)) {
					LDAPModification ldapModification = new LDAPModification(
							LDAPModification.DELETE, new LDAPAttribute(
									"member", userEntry.getDN()));
					debugModifications("Removing group member ",
							groupEntry.getDN(),
							new LDAPModification[] { ldapModification });
					c.modify(groupEntry.getDN(), ldapModification);
					postDeleteTrigger(
							generateAccountName(groupEntry, null, "name"),
							userName, groupEntry,
							userEntry);
				}
			}
		} catch (LDAPException e) {
			handleException(e, c);
			throw e;
		} finally {
			returnConnection(domain);
		}
	}

	private void addGroupMember(String group, String user, LDAPEntry userEntry)
			throws Exception {
		Grup soffidGroup = null;
		Rol soffidRole = null;
		ExtensibleObjects eo = null;
		ExtensibleObject targetObject = new ExtensibleObject();
		RolGrant grant = new RolGrant();
		grant.setOwnerAccountName(user);
		grant.setOwnerDispatcher(getDispatcher().getCodi());
		ExtensibleObject sourceObject = new GrantExtensibleObject(grant,
				getServer());
		try {
			soffidGroup = getServer().getGroupInfo(group,
					getDispatcher().getCodi());
			eo = objectTranslator
					.generateObjects(new GroupExtensibleObject(soffidGroup,
							getDispatcher().getCodi(), getServer()));
		}

		catch (UnknownGroupException e) {
			soffidRole = getServer().getRoleInfo(group,
					getDispatcher().getCodi());
			eo = objectTranslator.generateObjects(new RoleExtensibleObject(
					soffidRole, getServer()));
		}

		if (eo.getObjects().isEmpty())
			return;
		
		for (ExtensibleObject object: eo.getObjects())
		{
			String objectClass = vom.toSingleString( object.getAttribute("objectClass") );
			if (objectClass.toLowerCase().contains("group")) // Ignore OUs
			{
				LDAPEntry groupEntry = searchSamAccount(eo.getObjects().get(0),
						group);
				
				// No existing group
				if (groupEntry == null) {
					if (soffidGroup != null)
					{
						log.info("Creating group "+soffidGroup);
						updateGroup(group, soffidGroup);						
					}
					if (soffidRole != null)
					{
						log.info("Creating role "+soffidRole);
						updateRole(soffidRole);
					}
					groupEntry = searchSamAccount(eo.getObjects().get(0), group);
				}
				
				if (groupEntry != null
						&& preInsertTrigger(group, user, groupEntry, userEntry)) {
					String domain = searchDomainForDN(groupEntry.getDN());
					if (multiDomain) { 
						String domain2 = searchDomainForDN(userEntry.getDN());
						if (! domain2.equals(domain))
						{
							LDAPAttribute groupTypeAtt = groupEntry.getAttribute("groupType");
							if (groupTypeAtt != null && groupTypeAtt.getStringValue() != null)
							{
								long groupType = Long.decode(groupTypeAtt.getStringValue()).longValue();
								if (groupType < 0) groupType += 2147483648L;
								if ( (groupType & 8) == 0 && (groupType & 4) == 0 )
								{
									log.warn("Cannot asign group "+groupEntry.getDN()+" to "+userEntry.getDN()+": Group has not UNIVERSAL nor LOCAL scope");
									return;
								}
							}
						}
					}
					log.info("Adding user {} to group {}", user, group);
					LDAPConnection conn = getConnection(domain);
					try {
						LDAPModification ldapModification = new LDAPModification(
								LDAPModification.ADD, new LDAPAttribute("member",
										userEntry.getDN()));
						debugModifications("Adding group member ", groupEntry.getDN(),
								new LDAPModification[] { ldapModification });
						conn.modify(groupEntry.getDN(), ldapModification);
						log.info("Added", null, null);
						postInsertTrigger(group, user, groupEntry, userEntry);
					} catch (LDAPException e) {
						handleException(e, conn);
						// Ignore when adding a new group membership that is included as primary group id
						if (e.getResultCode() != LDAPException.ENTRY_ALREADY_EXISTS)
							throw e;
					} finally {
						returnConnection(domain);
					}
					
				}
				
			}
		}

	}

	public void updateUser(String accountName, String description)
			throws RemoteException, InternalErrorException {
		Account account = getServer().getAccountInfo(accountName, getCodi());
		AccountExtensibleObject sourceObject = new AccountExtensibleObject(
				account, getServer());
		ExtensibleObjects objects = objectTranslator
				.generateObjects(sourceObject);

		Watchdog.instance().interruptMe(getDispatcher().getTimeout());
		try {
			String oldAccountName = getAccountName (account);
			updateObjects(oldAccountName, accountName, objects, sourceObject, null /*always apply*/, !account.isDisabled());
			for (ExtensibleObject object : objects.getObjects()) {
				if ("user".equalsIgnoreCase((String) object.getAttribute("objectClass"))) {
					updateUserStatus(accountName, object, !account.isDisabled(), new AccountExtensibleObject(account, getServer()), null);
					updateUserGroups(accountName, object, ! account.isDisabled(), null /*always apply */);
				}
			}
		} catch (LDAPException e) {
			throw new InternalErrorException(e.getMessage());
		} catch (UnknownUserException e) {
			throw new InternalErrorException(e.getMessage());
		} catch (UnknownRoleException e) {
			throw new InternalErrorException(e.getMessage());
		} catch (InternalErrorException e) {
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException(e.getMessage(), e);
		} finally {
			Watchdog.instance().dontDisturb();
		}

	}

	private String getAccountName(Account account) throws InternalErrorException {
		if (oldNameGetter != null )
		{
			String oldName;
			try {
				oldName = (String) oldNameGetter.invoke(account);
			} catch (Exception e) {
				throw new InternalErrorException ("Error getting old account name", e);
			}
			if (oldName != null)
				return oldName;
		}
		return account.getName();
	}


	public void removeUser(String userName) throws RemoteException,
			InternalErrorException {
		
		boolean realRemove = false;

		Account account = getServer().getAccountInfo(userName, getCodi());
		if (account == null)
		{
			realRemove = true;
			account = new Account();
			account.setName(userName);
			account.setDescription(userName);
			account.setDisabled(true);
			account.setDispatcher(getDispatcher().getCodi());
		}
		else if (account.getStatus() == AccountStatus.REMOVED)
		{
			realRemove = true;
		}
		ExtensibleObjects objects;
		ExtensibleObject sourceObject;

		
		try {
			Usuari user = getServer().getUserInfo(userName,
					getDispatcher().getCodi());
			objects = objectTranslator
					.generateObjects(sourceObject = new UserExtensibleObject(
							account, user, getServer()));
		} catch (UnknownUserException e) {
			objects = objectTranslator
					.generateObjects(sourceObject = new AccountExtensibleObject(
							account, getServer()));
		}
		Watchdog.instance().interruptMe(getDispatcher().getTimeout());
		try {
			if ( realRemove)
			{
				for (ExtensibleObject object : objects.getObjects()) {
					updateUserStatus(userName, object, false, sourceObject, null /*always apply*/);
					updateUserGroups(userName, object, false, null /*always apply */);
				}
				removeObjects(userName, objects, sourceObject, null /*always apply*/);
			} else {
				for (ExtensibleObject object : objects.getObjects()) {
					ExtensibleObjectMapping mapping = getMapping (object.getObjectType());
					
					if ("true".equals(mapping.getProperties().get("createDisabledAccounts")) || 
							searchSamAccount(object, userName) != null)
					{
						if (multiDomain && userName.contains("\\"))
							object.setAttribute(SAM_ACCOUNT_NAME_ATTRIBUTE, userName.toLowerCase().split("\\\\")[1]);
						else
							object.setAttribute(SAM_ACCOUNT_NAME_ATTRIBUTE, userName.toLowerCase());
						updateObject(userName, userName, object, sourceObject, null /*always apply*/, false);
						updateUserStatus(userName, object, false, sourceObject, null /*always apply*/);
						updateUserGroups(userName, object, false, null /*always apply */);
					}
				}
			}
		} catch (InternalErrorException e) {
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException(e.getMessage(), e);
		} finally {
			Watchdog.instance().dontDisturb();
		}

	}

	public void updateUserPassword(String userName, Usuari userData,
			Password password, boolean mustchange) throws RemoteException,
			InternalErrorException {
		Account account = getServer().getAccountInfo(userName, getDispatcher().getCodi()); 
		
		ExtensibleObjects objects = null;
		ExtensibleObject sourceObject;
		if (userData != null)
			objects = objectTranslator
					.generateObjects(sourceObject = new UserExtensibleObject(
							account, userData, getServer()));

		else
			objects = objectTranslator
					.generateObjects(sourceObject = new AccountExtensibleObject(
							account, getServer()));

		Watchdog.instance().interruptMe(getDispatcher().getTimeout());
		try {
			updatePassword(sourceObject, userName, objects, password,
					mustchange, !account.isDisabled());
		} catch (InternalErrorException e) {
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException(e.getMessage(), e);
		} finally {
			Watchdog.instance().dontDisturb();
		}

	}

	public void updateRole(Rol rol) throws RemoteException,
			InternalErrorException {
		if (rol.getBaseDeDades().equals(getDispatcher().getCodi())) {
			Watchdog.instance().interruptMe(getDispatcher().getTimeout());
			try {
				if (rol.getNom().startsWith("\\\\") || rol.getNom().startsWith("//")) {
					setAcl(rol);

				} else {
					RoleExtensibleObject sourceObject = new RoleExtensibleObject(rol,
							getServer());
					ExtensibleObjects objects = objectTranslator
							.generateObjects(sourceObject);
						updateObjects(rol.getNom(), rol.getNom(), objects, sourceObject, null /*always apply*/, true);
          if (useNestedGroups()) {
            if (isDebug())
              log.info("BEGIN Updating role members");
            try {
              for (ExtensibleObject object : objects.getObjects()) {
                if ("group".equalsIgnoreCase((String) object.getAttribute("objectClass"))) {
                  updateRoleGroups(rol, object, true, null);
                }
              }
            } finally {
              if (isDebug())
                log.info("END");
              
            }
          }
				}
			} catch (InternalErrorException e) {
				throw e;
			} catch (Exception e) {
				throw new InternalErrorException(e.getMessage(), e);
			} finally {
				Watchdog.instance().dontDisturb();
			}
		}
	}

	private void setAcl(Rol rol) throws Exception {
		final String[] authData = nasManager.parseAuthData(new HashMap<String, Object>());
		List<String[]> newAcls = fetchNewAcl(rol);	
		
		nasManager.setAcl(rol.getNom(), newAcls, authData);
	}


	private List<String[]> fetchNewAcl(Rol rol) throws InternalErrorException, IOException {
		Map<String, String> r = new HashMap<>();
		for (RolGrant grant: rol.getOwnerRoles()) 
		{
			if (getCodi().equals(grant.getOwnerDispatcher())) {
				String name = grant.getOwnerRolName();
				String prev = r.get(name);
				if (prev == null)
					r.put(name, grant.getDomainValue());
				else
					r.put(name, prev+" "+grant.getDomainValue());
			}
		}
		
		final ApplicationService applicationService = new RemoteServiceLocator().getApplicationService();
		for (RoleGrant grant: applicationService.findEffectiveRoleGrantsByRoleId(rol.getId())) {
			boolean skipGrant = false;
			if (grant.getOwnerRole() != null) {
				Role role2 = applicationService.findRoleById(grant.getOwnerRole());
				if (role2.getSystem().equals(rol.getBaseDeDades()))
					skipGrant = true;
			}
			if (!skipGrant) {
				String name = grant.getOwnerAccountName();
				String prev = r.get(name);
				if (prev == null)
					r.put(name, grant.getDomainValue());
				else
					r.put(name, prev+" "+grant.getDomainValue());

			}
		}
		List<String[]> result = new LinkedList<>();
		for (Entry<String, String> entry: r.entrySet()) {
			result.add(new String[] { entry.getKey(), entry.getValue(), "CONTAINER_INHERIT_ACE OBJECT_INHERIT_ACE"});
		}
		return result ;
	}


	public void removeRole(String rolName, String dispatcher)
			throws RemoteException, InternalErrorException {
		Rol rol = new Rol();
		rol.setNom(rolName);
		rol.setBaseDeDades(dispatcher);
		RoleExtensibleObject sourceObject = new RoleExtensibleObject(rol,
				getServer());
		ExtensibleObjects objects = objectTranslator
				.generateObjects(sourceObject);
		Watchdog.instance().interruptMe(getDispatcher().getTimeout());
		try {
			removeObjects(rolName, objects, sourceObject, null /*always apply*/);
		} catch (InternalErrorException e) {
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException(e.getMessage(), e);
		} finally {
			Watchdog.instance().dontDisturb();
		}
	}

	public void updateGroup(String key, Grup grup) throws RemoteException,
			InternalErrorException {
		GroupExtensibleObject sourceObject = new GroupExtensibleObject(grup,
				getDispatcher().getCodi(), getServer());
		ExtensibleObjects objects = objectTranslator
				.generateObjects(sourceObject);
		Watchdog.instance().interruptMe(getDispatcher().getTimeout());
		try {
			updateObjects(key, key, objects, sourceObject, null /*always apply*/, true);
		} catch (InternalErrorException e) {
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException(e.getMessage(), e);
		} finally {
			Watchdog.instance().dontDisturb();
		}
	}

	public void removeGroup(String key) throws RemoteException,
			InternalErrorException {
		Grup grup = new Grup();
		grup.setCodi(key);
		GroupExtensibleObject sourceObject = new GroupExtensibleObject(grup,
				getDispatcher().getCodi(), getServer());
		ExtensibleObjects objects = objectTranslator
				.generateObjects(sourceObject);
		Watchdog.instance().interruptMe(getDispatcher().getTimeout());
		try {
			removeObjects(key, objects, sourceObject, null /*always apply*/);
		} catch (InternalErrorException e) {
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException(e.getMessage(), e);
		} finally {
			Watchdog.instance().dontDisturb();
		}
	}

	public KerberosPrincipalInfo createServerPrincipal(String server)
			throws InternalErrorException {
		try {
			log.info("Creating principal for server "+server);
			String uid;
			String principal;
			if (server.contains("/")) {
				principal = server;
				uid = server.replace('/', '_');
			} else {
				uid = "SEYCON_" + server;
				if (uid.indexOf('.', 11) > 0)
					uid = uid.substring(0, uid.indexOf('.', 11));
				if (uid.length() > 20) {
					MessageDigest d = MessageDigest.getInstance("MD5");
					byte data[] = d.digest(server.getBytes("UTF-8"));
					uid = "SOFFID_" + Base64.encodeBytes(data, Base64.DONT_BREAK_LINES);
					uid = uid.substring(0, 20);
				}
				principal = "SEYCON/" + server;
			}
			log.info("Account name:    "+uid);
			log.info("Server principal: "+principal);

			
			String realm = getRealmName();
			KerberosPrincipalInfo result = new KerberosPrincipalInfo();
			result.setUserName(uid);
			result.setPrincipalName(principal + "@" + realm);
			result.setPassword(getServer().generateFakePassword(
					getDispatcher().getDominiContrasenyes()));

			ExtensibleObject object = new ExtensibleObject();
			object.setObjectType("account");
			object.setAttribute("accountName", uid);
			object.setAttribute("accountDescription", "Kerberos account for "
					+ server);

			ExtensibleObjects ldapObjects = objectTranslator
					.generateObjects(object);

			for (ExtensibleObject ldapObject : ldapObjects.getObjects()) {
				LDAPEntry entry = searchSamAccount(ldapObject, uid);
				String dn = getDN(ldapObject, null);
				String domain = searchDomainForDN(dn); 
				LDAPConnection lc = getConnection(domain);
				if (entry == null) 
					entry = findByServiceName(lc, domain, principal);
				try {
					if (entry == null) {
						ldapObject
								.setAttribute(SAM_ACCOUNT_NAME_ATTRIBUTE, uid);
						// New user object
						LDAPAttributeSet attributeSet = new LDAPAttributeSet();
						for (String attribute : ldapObject.getAttributes()) {
							String values[] = toStringArray(ldapObject
									.getAttribute(attribute));
							if (values != null && !"dn".equals(attribute)
									&& !BASE_DN.equals(attribute) 
									&& !RELATIVE_DN.equals(attribute)) {
								log.info("Adding attribute {}={}", attribute,
										values);
								attributeSet.add(new LDAPAttribute(attribute,
										values));
							}
						}

						// Bind to be run as a service
						attributeSet.add(new LDAPAttribute(
								USER_ACCOUNT_CONTROL,
								Integer.toString(ADS_UF_ACCOUNTDISABLE
										| ADS_UF_NORMAL_ACCOUNT
										| ADS_UF_TRUSTED_FOR_DELEGATION)));

						attributeSet.add(new LDAPAttribute(
								"servicePrincipalName", principal));
						log.info("Adding attribute {}={}",
								"servicePrincipalName", principal);

						entry = new LDAPEntry(dn, attributeSet);
						log.warn("Creating {}", dn, null);
						lc.add(entry);
					} else {
						// Check service principal name
						LDAPAttribute att = entry.getAttribute("servicePrincipalName");
						boolean found = false;
						if (att != null)
						{
							for (String v: att.getStringValueArray())
							{
								if (v.equals (principal)) found = true;
							}
						}
						if (! found)
						{
							LDAPModification[] mods = new LDAPModification[] {
									new LDAPModification(LDAPModification.ADD,
											new LDAPAttribute("servicePrincipalName", principal)) 
									};
							debugModifications("Assigning service principal name ", entry.getDN(),
									mods);
							lc.modify(entry.getDN(), mods);
						}
					}

					String s = entry.getAttribute(USER_ACCOUNT_CONTROL).getStringValue();
					log.info("Status = " +s);
					int status = Integer.parseInt(s);
					log.info("TRUSTED FOR DELEGATION: " + ( (status & ADS_UF_TRUSTED_FOR_DELEGATION) != 0 ? "YES": "NO" ));
					log.info("EXPIRE PASSWD: " + ( (status & ADS_UF_DONT_EXPIRE_PASSWD) != 0 ? "NO": "YES" ));
					// Asign the password
					byte v[] = encodePassword(result.getPassword());
					LDAPAttribute atributo = new LDAPAttribute("unicodePwd", v);
					status = ADS_UF_NORMAL_ACCOUNT
							| ADS_UF_DONT_EXPIRE_PASSWD
							| ADS_UF_TRUSTED_FOR_DELEGATION;

					LDAPModification[] mods;
					
					if (!lc.isTLS()){
						updateSamPassword (domain, uid, result.getPassword(), false);
						mods = new LDAPModification[] {
								new LDAPModification(LDAPModification.REPLACE,
										new LDAPAttribute(USER_ACCOUNT_CONTROL,
												Integer.toString(status))) 
								};
					} else {
						mods = new LDAPModification[] {
								new LDAPModification(LDAPModification.REPLACE,
										atributo)
								 ,
								new LDAPModification(LDAPModification.REPLACE,
										new LDAPAttribute(USER_ACCOUNT_CONTROL,
												Integer.toString(status))) 
								};
					}

					debugModifications("Updating kerberos principal ", entry.getDN(),
							mods);
					lc.modify(entry.getDN(), mods);

					return result;
				} catch (LDAPException e) {
					handleException(e, lc);
					throw e;
				} finally {
					returnConnection(domain);
				}
			}
			return null;
		} catch (LDAPException e) {
			log.warn("Error creating kerberos principal"+e.getMessage());
			throw new InternalErrorException(e.toString(), e);
		} catch (IOException e) {
			log.warn("Error creating service principal"+e.getMessage());
			throw new InternalErrorException(e.toString(), e);
		} catch (TimedOutException e) {
			log.warn("Error creating service principal"+e.getMessage());
			throw new InternalErrorException(e.toString(), e);
		} catch (InternalErrorException e) {
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException(e.getMessage(), e);
		}
	}

	private LDAPEntry findByServiceName(LDAPConnection conn, String domain, String serviceName) throws Exception {
		LDAPEntry entry;
		String queryString;

		queryString = "(&(objectClass=user)(servicePrincipalName=" + escapeLDAPSearchFilter(serviceName) + "))";
		if (debugEnabled)
			log.info("Searching for object "+queryString+" on domain "+domain);
		LDAPSearchConstraints constraints = new LDAPSearchConstraints(conn.getConstraints());
		LDAPSearchResults search = conn.search(domain,
				LDAPConnection.SCOPE_SUB, queryString, null, false,
				constraints);
		while (search.hasMore()) {
			try {
				entry = search.next();
				return entry;
			} catch (LDAPReferralException ldapError) {
				if (followReferrals)
					throw ldapError;
			}
		}
		return null;
	}

	private byte[] encodePassword(Password p) throws InternalErrorException {
		try {
			return ("\"" + p.getPassword() + "\"").getBytes("UTF-16LE");
		} catch (UnsupportedEncodingException e) {
			throw new InternalErrorException("Error generating password: "
					+ e.toString(), e);
		}
	}

	public String getRealmName() {
		String parts[] = LDAPDN.explodeDN(baseDN, true);
		StringBuffer realm = new StringBuffer();
		for (int i = 0; i < parts.length; i++) {
			if (i > 0)
				realm.append(".");
			realm.append(parts[i].toUpperCase());
		}
		return realm.toString();
	}

	public String[] getRealmServers() throws InternalErrorException {
		try {
			InetAddress[] addrs = InetAddress.getAllByName(getRealmName());
			String result[] = new String[addrs.length];
			for (int i = 0; i < result.length; i++) {
				result[i] = addrs[i].getHostAddress();
			}
			return result;
		} catch (UnknownHostException e) {
			throw new InternalErrorException("Unknown host " + getRealmName(),
					e);
		}
	}

	HashMap<String, String> pendingChanges = new HashMap<String, String>();

	
	protected LinkedList<ExtensibleObject> getLdapObjects(LdapSearch search) throws Exception {
		log.info("Searching for changes");

		int count = 0;
		
		LinkedList<ExtensibleObject> objects = new LinkedList<ExtensibleObject>();
		if ( !search.finished)
		{
			if (debugEnabled) {
				if (search.searchCookie == null)
					log.info("Looking for objects: LDAP QUERY=" + search.queryString
						+ " on " + search.searchBaseDN);
				else
					log.info("Looking for objects: LDAP QUERY=" + search.queryString
							+ " on " + search.searchBaseDN+" cookie "+Base64.encodeBytes(search.searchCookie, Base64.DONT_BREAK_LINES));
			}

			LDAPConnection lc = getConnection(search.domain);
			try {
				LDAPPagedResultsControl pageResult = new LDAPPagedResultsControl(
						lc.getSearchConstraints().getMaxResults(), true);
				pageResult.setCookie(search.searchCookie);

				if (debugEnabled)
					log.info("Page size: "
							+ lc.getSearchConstraints().getMaxResults());
				
				LDAPSearchConstraints constraints = new LDAPSearchConstraints(lc.getConstraints());
				constraints.setControls(pageResult);
				constraints.setBatchSize(100);
				constraints.setServerTimeLimit( 
						getDispatcher().getLongTimeout() == null ? 0: 
							getDispatcher().getLongTimeout().intValue());
				lc.setConstraints(constraints);

				LDAPSearchResults searchResults = lc.search(search.searchBaseDN,
						LDAPConnection.SCOPE_SUB, search.queryString,
						null, false);

				// Process results
				while (searchResults.hasMore()) {
					boolean add = false;
					LDAPEntry entry = null;
					try {
						entry = searchResults.next();
					} catch (LDAPReferralException ldapError) {
						if (followReferrals)
							throw ldapError;
					} catch (LDAPException e) {
						if (e.getResultCode() == LDAPException.NO_SUCH_OBJECT) {
							// Ignore
						} else {
							log.debug("LDAP Exception: "+e.toString());
							log.debug("ERROR MESSAGE: "+e.getLDAPErrorMessage());
							log.debug("LOCALIZED MESSAGE: "+e.getLocalizedMessage());
							throw e;
						}
					}
					if (entry != null) {
						count ++;
						String lastChange = pendingChanges .get(entry.getDN());
						LDAPAttribute lastChangeAttribute = entry .getAttribute("uSNChanged");

						Long changeId;
						if (lastChangeAttribute != null) {
							changeId = Long .decode(lastChangeAttribute .getStringValue());
							if (lastUploadedChange == null || lastUploadedChange.longValue() < changeId.longValue())
								lastUploadedChange = changeId;
						}

						ExtensibleObject eo = parseEntry(entry, search.mapping);
						objects .add(eo);
					}
				}

				LDAPControl[] responseControls = searchResults.getResponseControls();
				search.finished = true;
				if (responseControls != null) {
					log.info("Got response control");
					for (int i = 0; i < responseControls.length; i++) {
						if (responseControls[i] instanceof LDAPPagedResultsResponse) {
							LDAPPagedResultsResponse response = (LDAPPagedResultsResponse) responseControls[i];
							if (response.getCookie() != null) {
								search.searchCookie = response.getCookie();
								if (debugEnabled)
									log.info("LDAP results pending");
								search.finished = false;
							}
						}
					}
				}
				if (debugEnabled)
					log.info("Fetched " + count + " loaded");
			} catch (Exception e) {
				handleException(e, lc);
				throw new InternalErrorException(e.getMessage(), e);
			} finally {
				returnConnection(mainDomain);
			}
		}
		return objects;
	}

	private Long lastUploadedChange = null;

	protected Stack<LdapSearch> searches = null;

	private boolean readOnly = false;
	public Collection<AuthoritativeChange> getChanges(String nextChange)
			throws InternalErrorException {
		Collection<AuthoritativeChange> changes = new LinkedList<AuthoritativeChange>();
		Watchdog.instance().interruptMe(getDispatcher().getLongTimeout());
		try {
			log.info("Getting changes from " + nextChange);
			if (searches == null)
			{
				searches = new Stack<CustomizableActiveDirectoryAgent.LdapSearch>();
				for (String domain: domainHost.keySet())
				{
					for (ExtensibleObjectMapping mapping : objectMappings) {
						if (mapping.getSoffidObject().equals(SoffidObjectType.OBJECT_USER) ||
								mapping.getSoffidObject().equals(SoffidObjectType.OBJECT_GROUP) || 
								mapping.getSoffidObject().toString().equals("custom")) {
							searches.push( new LdapSearch(mapping, domain, nextChange) );
							if (debugEnabled)
								log.info("Planned search on domain "+domain);
						}
					}
				}
			}
			LdapSearch currentSearch = null;
			while ( changes.isEmpty())
			{
				do
				{
					if (searches.isEmpty())
						return changes;
					LdapSearch s = searches.peek();
					if (s.finished)
					{
						if (debugEnabled)
							log.info("Finished search on domain "+s.domain);
						searches.pop();
					}
					else
						currentSearch = s;
				} while (currentSearch == null);
					
				log.info("Searching on "+currentSearch.domain);
				LinkedList<ExtensibleObject> objects = getLdapObjects(currentSearch);
	
				for (ExtensibleObject ldapObject : objects) 
				{
					if (debugEnabled)
					{
						debugObject("LDAP object", ldapObject, "  ");
					}
					ExtensibleObjects parsedObjects = objectTranslator
							.parseInputObjects(ldapObject);
					for (ExtensibleObject object : parsedObjects.getObjects()) {
						if (debugEnabled)
						{
							debugObject("Soffid object", object, "  ");
						}
						parseUser(changes, object, ldapObject);
						parseGroup(changes, object);
						parseCustomObject(changes, object);
					}
				}
			}
		} catch (LDAPException e) {
			throw new InternalErrorException("Error getting accounts list", e);
		} catch (InternalErrorException e) {
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException(e.getMessage(), e);
		} finally {
			Watchdog.instance().dontDisturb();
		}
		return changes;
	}


	private void parseUser(Collection<AuthoritativeChange> changes, ExtensibleObject object, ExtensibleObject ldapObject)
			throws InternalErrorException {
		AuthoritativeChange change = parseUserChange(object, ldapObject);
		if (change != null)
			changes.add(change);
	}


	public AuthoritativeChange parseUserChange(ExtensibleObject object, ExtensibleObject ldapObject) throws InternalErrorException {
		AuthoritativeChange change = null;
		Usuari user = vom.parseUsuari(object);
		if (user != null) {
			if ( user.getActiu() == null) {
				Object uac = ldapObject.get("userAccountControl");
				if (uac != null) {
					user.setActiu( ( Long.parseLong(uac.toString()) & 2 )== 0 );
				}
			}
			change = new AuthoritativeChange();
			change.setSourceSystem(getCodi());

			AuthoritativeChangeIdentifier id = new AuthoritativeChangeIdentifier();
			change.setId(id);
			id.setChangeId(null);
			id.setEmployeeId("user:"+user.getCodi());
			id.setDate(new Date());

			change.setUser(user);

			Object groups = object.getAttribute("secondaryGroups");
			if (groups instanceof Collection) {
				Set<String> groupsList = new HashSet<String>();
				for (Object group : (Collection<Object>) object) {
					if (group instanceof String) {
						groupsList.add((String) group);
					} else if (group instanceof ExtensibleObject) {
						Object name = (String) ((ExtensibleObject) group)
								.getAttribute("name");
						if (name != null)
							groupsList.add(name.toString());
					} else if (group instanceof Group) {
						groupsList.add(((Group) group).getName());
					} else if (group instanceof Grup) {
						groupsList.add(((Grup) group).getCodi());
					}
				}
				change.setGroups(groupsList);
			}

			Object attributes = object.getAttribute("attributes");
			if (attributes instanceof Map) {
				Map<String, Object> attributesMap = new HashMap<String, Object>();
				for (Object attributeName : ((Map) attributes)
						.keySet()) {
					Object attValue = vom
									.toSingleton(((Map) attributes)
											.get(attributeName));
					if (attValue == null)
						attributesMap.put((String) attributeName, null);
					else if (attValue instanceof Date ||
							attValue instanceof Calendar)
						attributesMap.put((String) attributeName, attValue);
					else
						attributesMap.put((String) attributeName, attValue.toString());
				}
				change.setAttributes(attributesMap);
			}

		}
		return change;
	}


	private void parseGroup(Collection<AuthoritativeChange> changes, ExtensibleObject object)
			throws InternalErrorException {
		AuthoritativeChange change = parseGroupChange(object);
		if (change != null)
			changes.add(change);
	}


	public AuthoritativeChange parseGroupChange(ExtensibleObject object) throws InternalErrorException {
		AuthoritativeChange change = new AuthoritativeChange();
		Grup group = vom.parseGroup(object);
		if (group != null) {
			change = new AuthoritativeChange();

			change.setSourceSystem(getCodi());
			AuthoritativeChangeIdentifier id = new AuthoritativeChangeIdentifier();
			change.setId(id);
			id.setChangeId(null);
			id.setEmployeeId("group:"+group.getCodi());
			id.setDate(new Date());

			change.setGroup(group);
		}
		return change;
	}

	protected void parseCustomObject(Collection<AuthoritativeChange> changes, ExtensibleObject object) throws InternalErrorException {
		AuthoritativeChange change = parseCustomObjectChange(object);
		if (change != null)
			changes.add(change);
	}

	protected AuthoritativeChange parseCustomObjectChange(ExtensibleObject object) 
		throws InternalErrorException
	{
		return null;
	}


	public boolean hasMoreData() throws InternalErrorException {
		return !searches.isEmpty();
	}

	public String getNextChange() throws InternalErrorException {
		if (lastUploadedChange == null || multiDomain)
			return null;
		else
			return Long.toString(lastUploadedChange.longValue() + 1);
	}

	public void debugModifications(String action, String dn,
			LDAPModification mods[]) {
		if (debugEnabled) {
			log.info("=========================================================");
			log.info(action + " object " + dn);
			for (int i = 0; i < mods.length; i++) {
				LDAPModification mod = mods[i];
				debugAttribute(mod.getOp(), mod.getAttribute());
			}
			log.info("=========================================================");
		}
	}

	public void debugModifications(String action, String dn,
			LDAPAttributeSet atts) {
		if (debugEnabled) {
			log.info("=========================================================");
			log.info(action + " object " + dn);
			for (Iterator iterator = atts.iterator(); iterator.hasNext();) {
				LDAPAttribute att = (LDAPAttribute) iterator.next();
				debugAttribute(LDAPModification.ADD, att);
			}
			log.info("=========================================================");
		}
	}

	public void debugEntry(String action, String dn, LDAPAttributeSet atts) {
		if (debugEnabled) {
			log.info("=========================================================");
			log.info(action + " object " + dn);
			for (Iterator iterator = atts.iterator(); iterator.hasNext();) {
				LDAPAttribute att = (LDAPAttribute) iterator.next();
				debugAttribute(-1, att);
			}
			log.info("=========================================================");
		}
	}

	private void debugAttribute(int op, LDAPAttribute ldapAttribute) {
		String attAction = op == -1 ? "" : op == LDAPModification.ADD ? "ADD"
				: op == LDAPModification.DELETE ? "DELETE" : "REPLACE";
		StringBuffer b = new StringBuffer(attAction);
		b.append(" ").append(ldapAttribute.getName());
		if (op != LDAPModification.DELETE) {
			b.append(" = [");
			if (ldapAttribute.getName().equalsIgnoreCase("unicodePwd")) {
				b.append("*****************");
			} else {
				String[] v = ldapAttribute.getStringValueArray();
				for (int j = 0; j < v.length; j++) {
					if (j > 0)
						b.append(", ");
					b.append(v[j]);
				}
			}
			b.append("]");
		}
		log.info(b.toString());
	}

	public Account getAccountInfo(String userAccount) throws RemoteException,
			InternalErrorException {
		ExtensibleObject eo;
		Watchdog.instance().interruptMe(getDispatcher().getTimeout());
		try {
			eo = findExtensibleUser(userAccount);
		} catch (LDAPException e) {
			throw new InternalErrorException(e.getMessage(), e);
		} catch (InternalErrorException e) {
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException(e.getMessage(), e);
		} finally {
			Watchdog.instance().dontDisturb();
		}

		if (eo == null)
			return null;
		ExtensibleObjects parsed = objectTranslator.parseInputObjects(eo);
		for (ExtensibleObject peo : parsed.getObjects()) {
			Account account = vom.parseAccount(peo);
			if (account != null) {
				account.setName(userAccount);
				if (account.getLoginName() == null) {
					if (multiDomain)
						account.setLoginName( userAccount );
					else {
						String domain =  domainToShortName.get(mainDomain);
						if (domain != null)
							account.setLoginName( domain + "\\" + userAccount);
					}
				}
				Object status = eo.getAttribute(USER_ACCOUNT_CONTROL);
				if (status != null) {
					Integer i = Integer.parseInt(status.toString());
					account.setDisabled((i & ADS_UF_ACCOUNTDISABLE) != 0);
				}
				if (debugEnabled)
					log.info("Got account " +account);
				return account;
			}
		}
		return null;
	}

	public List<RolGrant> getAccountGrants(String userAccount)
			throws RemoteException, InternalErrorException {
		Rol userRole; // User role
		LinkedList<RolGrant> rolesList = new LinkedList<RolGrant>(); // User
																		// roles
		LDAPEntry userEntry; // User LDAP entry
		Watchdog.instance().interruptMe(getDispatcher().getTimeout());
		try {
			if (debugEnabled)
				log.info("Finding user " + userAccount);
			ExtensibleObject eo = findExtensibleUser(userAccount);
			if (eo != null) {
				LDAPAttribute memberofattr; // User LDAP groups
				String userGroups[]; // User group array

				Object memberofattr1 = eo.getAttribute("dn");
				if (debugEnabled)
					log.info("Found DN = " + memberofattr1);
				userEntry = searchEntry(memberofattr1.toString());
				if (userEntry != null) {
					memberofattr = userEntry.getAttribute("memberOf");
					userGroups = (memberofattr == null ? new String[] {}
							: memberofattr.getStringValueArray());

					// Process the user groups
					for (int i = 0; i < userGroups.length; i++) {
						String groupName = userGroups[i];
						Rol r = rolesCache.get(groupName.toLowerCase());
						if (r != null)
						{
							log.info("User {} belongs to [{}]",
									userAccount, r.getNom());
							RolGrant rg = new RolGrant();
							rg.setOwnerAccountName(userAccount);
							rg.setRolName(r.getNom());
							rg.setDispatcher(getCodi());
							rg.setEnabled(true);
							rg.setOwnerDispatcher(getCodi());
							rolesList.add(rg);
						}
						else
						{
							LDAPEntry entry = searchEntry(userGroups[i], new String [] {"CN", "sAMAccountName"});
							if (entry == null)
								log.info("Warning: Cannot found group " + groupName);
							else if (entry.getAttribute(SAM_ACCOUNT_NAME_ATTRIBUTE) == null)
								log.info("Warning: Found group with no sAMAccountName: "
										+ groupName);
							else {
								for (ExtensibleObjectMapping mapping: objectMappings)
								{
									if (mapping.getSoffidObject().equals(SoffidObjectType.OBJECT_ROLE))
									{
										String roleName = generateAccountName(entry, mapping, "name");
										if (roleName != null)
										{
											log.info("User {} belongs to [{}]",
													userAccount, roleName);
											RolGrant rg = new RolGrant();
											rg.setOwnerAccountName(userAccount);
											rg.setRolName(roleName);
											rg.setDispatcher(getCodi());
											rg.setEnabled(true);
											rg.setOwnerDispatcher(getCodi());
											rolesList.add(rg);
										}
									}
								}
							}
						}
					}
				}
			}
		} catch (LDAPException e) {
			throw new InternalErrorException(e.getMessage());
		} catch (InternalErrorException e) {
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException(e.getMessage(), e);
		} finally {
			Watchdog.instance().dontDisturb();
		}

		return rolesList;
	}

	public static String escapeDN(String name) {
		StringBuffer sb = new StringBuffer(); // If using JDK >= 1.5 consider
												// using StringBuilder
		if ((name.length() > 0)
				&& ((name.charAt(0) == ' ') || (name.charAt(0) == '#'))) {
			sb.append('\\'); // add the leading backslash if needed
		}
		for (int i = 0; i < name.length(); i++) {
			char curChar = name.charAt(i);
			switch (curChar) {
			case '\\':
				sb.append("\\\\");
				break;
//			case ',':
//				sb.append("\\,");
//				break;
			case '+':
				sb.append("\\+");
				break;
			case '"':
				sb.append("\\\"");
				break;
			case '<':
				sb.append("\\<");
				break;
			case '>':
				sb.append("\\>");
				break;
			case ';':
				sb.append("\\;");
				break;
			default:
				sb.append(curChar);
			}
		}
		if ((name.length() > 1) && (name.charAt(name.length() - 1) == ' ')) {
			sb.insert(sb.length() - 1, '\\'); // add the trailing backslash if
												// needed
		}
		return sb.toString();
	}

	public static final String escapeLDAPSearchFilter(String filter) {
		StringBuffer sb = new StringBuffer(); // If using JDK >= 1.5 consider
												// using StringBuilder
		for (int i = 0; i < filter.length(); i++) {
			char curChar = filter.charAt(i);
			switch (curChar) {
			case '\\':
				sb.append("\\5c");
				break;
			case '*':
				sb.append("\\2a");
				break;
			case '(':
				sb.append("\\28");
				break;
			case ')':
				sb.append("\\29");
				break;
			case '\u0000':
				sb.append("\\00");
				break;
			default:
				sb.append(curChar);
			}
		}
		return sb.toString();
	}

	protected boolean preUpdate(ExtensibleObject soffidObject,
			ExtensibleObject adObject, LDAPEntry currentEntry)
			throws InternalErrorException {
		return true;
	}

	protected boolean preInsert(ExtensibleObject soffidObject,
			ExtensibleObject adObject) throws InternalErrorException {
		return true;
	}

	protected boolean preDelete(ExtensibleObject soffidObject,
			LDAPEntry currentEntry) throws InternalErrorException {
		return true;
	}

	protected boolean postUpdate(ExtensibleObject soffidObject,
			ExtensibleObject adObject, LDAPEntry currentEntry)
			throws InternalErrorException {
		return true;
	}

	protected boolean postInsert(ExtensibleObject soffidObject,
			ExtensibleObject adObject, LDAPEntry currentEntry)
			throws InternalErrorException {
		return true;
	}

	protected boolean postDelete(ExtensibleObject soffidObject,
			LDAPEntry currentEntry) throws InternalErrorException {
		return true;
	}

	protected boolean postInsertTrigger(String group, String user,
			LDAPEntry groupEntry, LDAPEntry userEntry)
			throws InternalErrorException {
		return true;
	}

	protected boolean preInsertTrigger(String group, String user,
			LDAPEntry groupEntry, LDAPEntry userEntry)
			throws InternalErrorException {
		return true;
	}

	protected boolean preDeleteTrigger(String stringValue, String userName,
			LDAPEntry groupEntry, LDAPEntry userEntry)
			throws InternalErrorException {
		return true;
	}

	protected boolean postDeleteTrigger(String stringValue, String userName,
			LDAPEntry groupEntry, LDAPEntry userEntry)
			throws InternalErrorException {
		return true;
	}

	protected boolean preSetPassword(ExtensibleObject soffidObject,
			ExtensibleObject object, Password password,
			LDAPEntry currentEntry)
			throws InternalErrorException {
		return true;
	}

	protected boolean postSetPassword(ExtensibleObject soffidObject,
			ExtensibleObject object, Password password,
			LDAPEntry currentEntry)
			throws InternalErrorException {
		return true;
	}

	protected void debugObject(String msg, Map<String, Object> obj,
			String indent) {
		if (debugEnabled) {
			if (indent == null)
				indent = "";
			if (msg != null)
				log.info(indent + msg);
			for (String attribute : obj.keySet()) {
				try {
					Object subObj = obj.get(attribute);
					if (subObj == null) {
						log.info(indent + attribute.toString() + ": <NULL>");
					} else if (subObj instanceof Map) {
						log.info(indent + attribute.toString() + ": Object {");
						debugObject(null, (Map<String, Object>) subObj, indent
								+ "   ");
						log.info(indent + "}");
					} else {
						log.info(indent + attribute.toString() + ": "
								+ subObj.toString());
					}
				} catch (Exception e ) {
					log.info(indent+ attribute.toString()+ ": "+e.toString());
				}
			}
		}
	}

	public class LdapSearch {
		public String domain;
		public ExtensibleObjectMapping mapping;
		public byte[] searchCookie = null;
		public String queryString = null;
		public String searchBaseDN = null;
		public boolean finished = false;
		public LdapSearch(ExtensibleObjectMapping mapping, String domain, String nextChange) throws InternalErrorException {
			this.domain = domain;
			String baseDN = domain;
			if (mapping.getProperties().containsKey("searchBase"))
				baseDN =  mapping.getProperties().get("searchBase")+","+baseDN;
			this.mapping = mapping;
			ExtensibleObject dummySoffidObj = new ExtensibleObject();
			LinkedList<ExtensibleObject> objects = new LinkedList<ExtensibleObject>();
			dummySoffidObj.setObjectType(mapping.getSoffidObject().getValue());

			ExtensibleObject dummySystemObject = objectTranslator
					.generateObject(dummySoffidObj, mapping, true);

			StringBuffer sb = new StringBuffer();
			sb.append("(&");
			boolean any = false;
			if (mapping.getProperties().containsKey(BASE_DN))
				searchBaseDN = mapping.getProperties().get(BASE_DN);
			else if (mapping.getProperties().get(RELATIVE_DN) != null &&
					!mapping.getProperties().get(RELATIVE_DN).isEmpty())
				searchBaseDN = baseDN + mapping.getProperties().get(RELATIVE_DN);
			else
				searchBaseDN = baseDN;
			if (mapping.getProperties().containsKey("searchQuery"))
				sb.append(mapping.getProperties().get("searchQuery"));
			else {
				for (String att : dummySystemObject.getAttributes()) {
					String value = vom.toSingleString(dummySystemObject
							.getAttribute(att));
					if ("objectClass".equalsIgnoreCase(att)) {
						if (value != null) {
							sb.append("(").append(att).append("=")
									.append(escapeLDAPSearchFilter(value))
									.append(")");
							any = true;
						}
					}
				}
			}
			
			if (nextChange != null && !multiDomain)
				sb.append("(uSNChanged>=")
						.append(escapeLDAPSearchFilter(nextChange))
						.append(")");
			sb.append("(!(objectClass=computer))");
			sb.append(")");
			if (any)
				queryString = sb.toString();
		}
	}

	public ExtensibleObject getNativeObject(SoffidObjectType type, String object1, String object2) 
			throws InternalErrorException 
	{
		return null;
	}


	public ExtensibleObject getSoffidObject(SoffidObjectType type, String object1, String object2) 
			throws InternalErrorException 
	{
		return null;
	}


	@Override
	public void createFolder(String folder, int type) throws RemoteException, InternalErrorException {
	}


	static Object lock = new Object();
	static Thread lastLogonThread = null;
	static HashMap<String, Thread> loadChangesThread = new HashMap<String, Thread>();
	Iterator<String> domainsIterator = null;
	Iterator<LDAPPool> controllersIterator = null;
	private String currentDomain;
	long lastIteration = 0;
	int phase = 0;

	@Override
	public Collection<LogEntry> getLogFromDate(Date From) throws RemoteException, InternalErrorException {
		synchronized (lock)
		{
			if ( "true".equals(extendedAttributes.get("realTimeLastLogin")) &&
					(lastLogonThread == null || ! lastLogonThread.isAlive()))
			{
				if (phase ==  0)
				{
					log.info("Starting load last logon thread");
					loadLastLogon();
				}
				else if (phase == 1)
				{
					loadLastPasswordChange();
				}
			}
			
			boolean auth = "true".equals(extendedAttributes.get("realTimeSource"));
			if (auth)
			{
				startLoadChangesThread();
			}
			else if ( !auth && loadChangesThread != null)
			{
				stopLoadChangesThread();
			}
		}
		return new LinkedList<LogEntry>();
	}

	private void stopLoadChangesThread() {
		for (String domain: new LinkedList<String>( loadChangesThread.keySet()))
		{
			Thread th = loadChangesThread.get(domain);
			if (th.isAlive())
				th.interrupt();
			else
				loadChangesThread.remove(domain);
		}
	}


	public void startLoadChangesThread() throws InternalErrorException {
		if (loadChangesThread == null)
			loadChangesThread = new HashMap<String,Thread>();
		log.info("Checking load changes thread status");
		for (String domain: domainHost.keySet())
		{
//			log.info("Checking load changes thread status for "+domain);
			LDAPPool pool = getPool(domain);
			List<LDAPPool> children = pool.getChildPools();
			if (children == null || children.isEmpty())
				createChildPools(pool);
			for (LDAPPool controller: pool.getChildPools()) {
				final String entryName = domain+" / "+controller.getLdapHost();
				log.info("Checking load changes thread status for "+entryName);
				Thread th = loadChangesThread.get(entryName);
				if (th == null || ! th.isAlive())
				{
					RealTimeChangeLoader2 rtl = new RealTimeChangeLoader2();
					rtl.setAgent(this);
					rtl.setAgentName(getDispatcher().getCodi());
					rtl.setBaseDn(domain);
					rtl.setDispatcher(getDispatcher());
					rtl.setDebugEnabled(debugEnabled);
					rtl.setDomainController(controller.getLdapHost());
					for ( ExtensibleObjectMapping mapping: objectMappings)
					{
						if (mapping.getSoffidObject().equals(SoffidObjectType.OBJECT_USER))
							rtl.setMaping(mapping);
					}
					rtl.setPool( controller );
					rtl.setTenant(getDispatcher().getTenant());
					th = new Thread ( rtl );
					th.setName("RealTimeChangeLoader "+domain+" "+controller.getLdapHost()+" @"+th.hashCode());
					th.start();
					
					loadChangesThread.put (entryName, th);
				}
			}			
		}
	}


	private void loadLastLogon() throws InternalErrorException {
		if (controllersIterator == null || ! controllersIterator.hasNext())
		{
			log.info("Getting list of domain controllers");
			if (domainsIterator == null || ! domainsIterator.hasNext())
			{
				long now = System.currentTimeMillis();
				if (now - lastIteration < 60 * 60 * 1000) // 1 hour
					return ;
				lastIteration = now;
				domainsIterator = domainHost.keySet().iterator();
			}
			currentDomain = domainsIterator.next();
			LDAPPool pool = getPool(currentDomain);
			List<LDAPPool> children = pool.getChildPools();
			if (children == null || children.isEmpty())
				createChildPools(pool);
			controllersIterator = pool.getChildPools().iterator();
		}
		if (controllersIterator != null && controllersIterator.hasNext())
		{
			LDAPPool domainControllerPool = controllersIterator.next();
			log.info("Polling last logon from domain controller "+domainControllerPool.getLdapHost());
			LastLoginLoader l = new LastLoginLoader();
			l.setAgentName(getCodi());
			l.setBaseDn( currentDomain );
			l.setDebugEnabled(debugEnabled);
			l.setPool(domainControllerPool);
			l.setDomainController(domainControllerPool.getLdapHost());
			l.setTenant( getDispatcher().getTenant() );
			ExtensibleObjectMapping m = null;
			for (ExtensibleObjectMapping mapping: objectMappings)
			{
				if (mapping.getSoffidObject().equals(SoffidObjectType.OBJECT_ACCOUNT))
					m = mapping;
			}
			l.setMaping (m);
			l.setAgent( this  );
			lastLogonThread = new Thread (l);
			lastLogonThread.start();
			if (! controllersIterator.hasNext() && ! domainsIterator.hasNext())
			{
				phase = 1;
				controllersIterator = null;
				domainsIterator = null;
			}
		}
	}

	private void loadLastPasswordChange() throws InternalErrorException {
		if (domainsIterator == null || ! domainsIterator.hasNext())
		{
			domainsIterator = domainHost.keySet().iterator();
		}
		currentDomain = domainsIterator.next();
		LDAPPool pool = getPool(currentDomain);

		LastPasswordChangeLoader l = new LastPasswordChangeLoader();
		l.setAgentName(getCodi());
		l.setBaseDn( currentDomain );
		l.setDebugEnabled(debugEnabled);
		l.setPool(pool);
		l.setTenant( getDispatcher().getTenant() );
		ExtensibleObjectMapping m = null;
		for (ExtensibleObjectMapping mapping: objectMappings)
		{
			if (mapping.getSoffidObject().equals(SoffidObjectType.OBJECT_ACCOUNT))
				m = mapping;
		}
		l.setMaping (m);
		l.setAgent( this  );
		lastLogonThread = new Thread (l);
		lastLogonThread.start();
		if (! domainsIterator.hasNext())
		{
			domainsIterator = null;
			phase = 0;
		}
	}

	public boolean supportsRename ()
	{
		return true;
	}

	public Collection<Map<String, Object>> invoke(String verb, String command,
			Map<String, Object> params) throws RemoteException, InternalErrorException 
	{
		Collection<Map<String, Object>> t = objectTranslator.getObjectFinder().invoke(verb, command, params);
		if (t == null)
			return null;
		LinkedList<Map<String, Object>> r = new LinkedList<Map<String,Object>>();
		for (Map<String, Object> tt: t)
		{
			if (tt instanceof LDAPExtensibleObject)
			{
				LDAPExtensibleObject leo = (LDAPExtensibleObject) tt;
				tt = new HashMap<String, Object>();
				for (String s: leo.keySet())
				{
					tt.put(s, leo.get(s));
				}
			}
			r.add(tt);
		}
		return r;
	}

	
	public List<String[]> getAccountChangesToApply (Account account) throws RemoteException, InternalErrorException {
		ExtensibleObject sourceObject ;
		Usuari u = null;
		try {
			u = getServer().getUserInfo(account.getName(), account.getDispatcher());
			sourceObject = new UserExtensibleObject( account, u, getServer());
		} catch (UnknownUserException e1) {
			sourceObject = new AccountExtensibleObject( account, getServer());
		}
		readOnly = true;
		List<String[]> changes = new LinkedList<String[]>();
		ExtensibleObjects objects = objectTranslator
				.generateObjects(sourceObject);

		Watchdog.instance().interruptMe(getDispatcher().getTimeout());
		try {
			String accountName = account.getName();
			String oldAccountName = getAccountName (account);
			if (account.getStatus() == AccountStatus.REMOVED)
			{
				removeObjects(accountName, objects, sourceObject, changes);
			}
			else
			{
				updateObjects(oldAccountName, accountName, objects, sourceObject, changes, !account.isDisabled() );
				for (ExtensibleObject object : objects.getObjects()) {
					if ("user".equalsIgnoreCase((String) object.getAttribute("objectClass"))) {
						if ( u == null)
							updateUserStatus(accountName, object, !account.isDisabled(), new AccountExtensibleObject(account, getServer()), changes);
						else
							updateUserStatus(accountName, object, !account.isDisabled(), new UserExtensibleObject(account, u, getServer()), changes);
						updateUserGroups(accountName, object, ! account.isDisabled(), changes);
					}
				}
			}
		} catch (LDAPException e) {
			throw new InternalErrorException(e.getMessage());
		} catch (UnknownUserException e) {
			throw new InternalErrorException(e.getMessage());
		} catch (UnknownRoleException e) {
			throw new InternalErrorException(e.getMessage());
		} catch (InternalErrorException e) {
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException(e.getMessage(), e);
		} finally {
			Watchdog.instance().dontDisturb();
		}
		return changes;

	}

	public List<String[]> getRoleChangesToApply (Rol role) throws RemoteException, InternalErrorException {
		ExtensibleObject sourceObject ;
		sourceObject = new RoleExtensibleObject( role, getServer());
		readOnly = true;
		List<String[]> changes = new LinkedList<String[]>();
		ExtensibleObjects objects = objectTranslator
				.generateObjects(sourceObject);

		Watchdog.instance().interruptMe(getDispatcher().getTimeout());
		try {
			String roleName = role.getNom();
			updateObjects(roleName, roleName, objects, sourceObject, changes, true );
			if (useNestedGroups()) {
				for (ExtensibleObject object : objects.getObjects()) {
					if ("group".equalsIgnoreCase((String) object.getAttribute("objectClass"))) {
						updateRoleGroups(role, object, true, changes);
					}
				}
			}
		} catch (LDAPException e) {
			throw new InternalErrorException(e.getMessage());
		} catch (UnknownUserException e) {
			throw new InternalErrorException(e.getMessage());
		} catch (UnknownRoleException e) {
			throw new InternalErrorException(e.getMessage());
		} catch (InternalErrorException e) {
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException(e.getMessage(), e);
		} finally {
			Watchdog.instance().dontDisturb();
		}
		return changes;
	}


	protected ObjectTranslator getObjectTranslator() {
		return objectTranslator;
	}


	/** 
	 *  Kerberos authentication
	 * @throws IOException 
	 * @throws LoginException 
	 * @throws NoSuchAlgorithmException 
	 */
	public String parseKerberosToken(final String serverPrincipal, byte[] keytab, final byte[] token)
			throws InternalErrorException {
		
		try {
			log.info("Parsing " + Base64.encodeBytes(token));
//			log.info("Parsing " + new String(token));
			KerberosSetup ks = startJaasSession(serverPrincipal, keytab);
			
			Object result = Subject.doAs(ks.subject, new PrivilegedAction<Object>() {
			    public Object run() {
			        try {
			        	new KerberosManager().generatDefaultKerberosConfig();
			            GSSManager manager = GSSManager.getInstance();
			        	Oid krb5Oid = new Oid("1.3.6.1.5.5.2"); // http://java.sun.com/javase/6/docs/technotes/guides/security/jgss/jgss-features.html
			        	GSSName gssName = manager.createName(serverPrincipal,null);
			        	GSSCredential serverCreds = manager.createCredential(gssName,GSSCredential.INDEFINITE_LIFETIME,krb5Oid,GSSCredential.ACCEPT_ONLY);
			        	GSSContext gContext = manager.createContext(serverCreds);
			        	
			        	if (gContext == null)
			        	{
			        		log.debug("SpnegoUserRealm: failed to establish GSSContext");
			        	}
			        	else
			        	{
			        		byte[] authToken = token;
			        		while (!gContext.isEstablished())
			        		{
			        			authToken = gContext.acceptSecContext(authToken,0,authToken.length);
			        		}
			        		if (gContext.isEstablished())
			        		{
			        			String clientName = gContext.getSrcName().toString();
			        			String role = clientName.substring(clientName.indexOf('@') + 1);
			        			
			        			log.info("SpnegoUserRealm: established a security context");
			        			log.info("Client Principal is: " + gContext.getSrcName());
			        			log.info("Server Principal is: " + gContext.getTargName());
			        			log.info("Client Default Role: " + role);
			        			
			        			
			        			return clientName;
			        		}
			        	}
			        	return null;
			        } catch (Exception e) {
			        	log.warn("Error parsing SPNEGO token", e);
			        	return null;
			        }
			    }
			});

			return (String) result;
		} catch (NoSuchAlgorithmException e) {
			throw new InternalErrorException("Error parsing keytab file", e);
		} catch (LoginException e) {
			throw new InternalErrorException("Error using keytab file for "+serverPrincipal, e);
		} catch (IOException e) {
			throw new InternalErrorException("Error configuring keytab file for "+serverPrincipal, e);
		}
	}
	
	public KerberosSetup startJaasSession (String principal, byte keytab[]) throws NoSuchAlgorithmException, IOException, LoginException {
		KerberosSetup ks = krbMap.get(principal);
		String keytab64 = Base64.encodeBytes(keytab);
		if (ks == null || ! ks.keytab64.equals(keytab64))
		{
			Config c = Config.getConfig();
			String fn = Hex.toHexString(Digest.getInstance("MD5").digest(principal.getBytes()));
			fn = fn.replaceAll("=", "");
			File f = new File ( new File(c.getHomeDir(), "conf"), fn+".keytab");
			FileOutputStream out = new FileOutputStream(f);
			out.write(keytab);
			out.close();
			// Generate spnego.conf file
			File f2 = new File ( new File(c.getHomeDir(), "conf"), fn+".conf");
			PrintStream out2 = new PrintStream (new FileOutputStream (f2));
			out2.println ("com.sun.security.jgss.krb5."+fn+" {");
			out2.println ("  com.sun.security.auth.module.Krb5LoginModule required");
			out2.println ("  principal=\""+principal+"\"");
			out2.println ("  useKeyTab=true");
			out2.println ("  keyTab=\""+f.getAbsolutePath()
				.replaceAll("\\\\", "\\\\\\\\")
				.replaceAll(":","\\\\:")+"\"");
			out2.println ("  debug=true");
			out2.println ("  storeKey=true");
			out2.println ("  isInitiator=false;");
			out2.println ("};");
			out2.close();
	        // Now perform login
	        Configuration cfg = Configuration.getInstance("JavaLoginConfig", new URIParameter(f2.toURI()));
	        ChainConfiguration.addConfiguration(cfg);
	        ks = new KerberosSetup();
	        ks.principal = principal;
	        ks.keytab64 = keytab64;
	        ks.id = fn;
	        ks.jaasDomain = "com.sun.security.jgss.krb5."+fn;
	        LoginContext lc = new LoginContext(ks.jaasDomain);
	        log.info("Trying login for {} ", principal);
	        lc.login();
            log.info("SUCCESSFULL Login", null, null);
            ks.subject = lc.getSubject();

            krbMap.put(principal, ks);
		}
		return ks;
	}
	Map<String,KerberosSetup> krbMap = new HashMap<String, KerberosSetup>();

	public String findPrincipalAccount(String principalName) throws InternalErrorException {
		int i = principalName.lastIndexOf("@");
		String account = principalName.substring(0, i);
		String dns = principalName.substring(i+1).toLowerCase();
		if ( !dnsNameToDomain.containsKey(dns)) {
			log.info("Not accepting dns name "+dns);
			return null;
		}
		try {
			log.info("Accepting dns name "+dns);
			LDAPEntry entry = findAccountInDomain (dnsNameToDomain.get(dns), account);
			if (entry == null) {
				log.info("Cannot find sAMAccountName "+account);
			} else {
				for ( ExtensibleObjectMapping mapping: objectMappings)
				{
					if (mapping.getSoffidObject().equals(SoffidObjectType.OBJECT_ACCOUNT))
					{
						String accountName = generateAccountName(entry, mapping, "accountName");
						if (accountName != null)
							return accountName;
					}
				}
			}
		} catch (Exception e) {
			throw new InternalErrorException ("Error searching for prinicipal "+principalName, e);
		}

		return null;
	}


	private LDAPEntry findAccountInDomain(String domain, String account) throws Exception {
		String queryString = "(&(objectClass=user)(sAMAccountName=" + escapeLDAPSearchFilter(account)+"))";
		
		LDAPConnection conn = getConnection(domain);
		try {
			LDAPSearchConstraints constraints = new LDAPSearchConstraints(conn.getConstraints());
			LDAPSearchResults query = conn.search(domain,
					LDAPConnection.SCOPE_SUB, queryString, null, false,
					constraints);
			while (query.hasMore()) {
				try {
					LDAPEntry entry = query.next();
					return entry;
				} catch (LDAPReferralException ldapError) {
					if (followReferrals)
						throw ldapError;
				}
			}
		} catch (LDAPException e) {
			handleException(e, conn);
			throw e;
		} finally {
			returnConnection(domain);
		}

		return null;
	}


	public String[] getDomainNames() throws InternalErrorException {
		Set<String> domains = new HashSet<>();
		domains.add(samDomainName);
		domains.addAll(shortNameToDomain.keySet());
		return domains.toArray(new String[domains.size()]);
	}


	public List getHostServices() throws RemoteException, InternalErrorException {
		return new LinkedList();
	}


	public String getAdministratorDN() {
		return administratorDN;
	}


	public void setAdministratorDN(String administratorDN) {
		this.administratorDN = administratorDN;
	}
}

class KerberosSetup
{
	public Subject subject;
	String principal;
	String keytab64;
	String id;
	String jaasDomain;
}
