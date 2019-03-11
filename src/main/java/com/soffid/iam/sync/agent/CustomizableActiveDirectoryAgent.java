package com.soffid.iam.sync.agent;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.UnknownHostException;
import java.rmi.RemoteException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Stack;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

import com.hierynomus.smbj.SMBClient;
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
import com.soffid.iam.utils.Security;
import com.soffid.msrpc.samr.SamrService;

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
import es.caib.seycon.ng.sync.intf.KerberosAgent;
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
		GroupMgr, KerberosAgent, AuthoritativeIdentitySource2 {

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
	/** ofuscador de claves SHA */
	MessageDigest digest;

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

	protected Map<String,String> domains = new HashMap<String, String>();
	protected Map<String,String> domainHost = new HashMap<String, String>();

	protected String mainDomain;

	protected boolean createOUs;

	private Method oldNameGetter;

	private String samDomainName;

	private String samAccountName;

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
		log.info("Starting Customizable Active Directory agent on {}",
				getDispatcher().getCodi(), null);
		loginDN = getDispatcher().getParam2();

		password = Password.decode(getDispatcher().getParam3());
		// password = params[1];
		ldapHost = getDispatcher().getParam0();
		baseDN = getDispatcher().getParam1();

		loginDN = loginDN.toLowerCase().contains(baseDN.toLowerCase()) || loginDN.contains("\\") ? loginDN 
				: loginDN + ", " + baseDN;
		
		multiDomain = "true".equals(getDispatcher().getParam4());
		createOUs = ! "false".equals(getDispatcher().getParam5());
		debugEnabled = "true".equals(getDispatcher().getParam7());
		trustEverything = "true".equals(getDispatcher().getParam8());
		// followReferrals = "true".equals(getDispatcher().getParam9());
		followReferrals = false;
		
		log.debug("Started ActiveDirectoryAgent user=" + loginDN,
//				+ " pass=" + password + "(" + password.getPassword() + ")",
				null, null);
		try {
			javaDisk = new bubu.util.javadisk();
		} catch (Throwable e) {
			// e.printStackTrace();
		}
		
		Watchdog.instance().interruptMe(getDispatcher().getTimeout());

		int start = baseDN.toLowerCase().indexOf("dc=");
		int end = baseDN.toLowerCase().indexOf(",", start);
		mainDomain = "";
		if (start >= 0)
		{
			if (end > 0)
				mainDomain = baseDN.substring(start+3, end ).toLowerCase();
			else
				mainDomain = baseDN.substring(start+3).toLowerCase();
		}
		domains.put(mainDomain, baseDN);
		domainHost.put(mainDomain, ldapHost.trim().split("[, ]+")[0]);
		reconfigurePool(mainDomain, ldapHost);

		try {
			oldNameGetter = Account.class.getMethod("getOldName",  new Class[0]);
		} catch (NoSuchMethodException e1) {
		} catch (SecurityException e1) {
		}
		LDAPConnection conn = null;
		try {
			conn = getConnection(mainDomain);
			if (multiDomain)
			{
				searchDomains (conn);
			}
			else
			{
				try {
					LDAPEntry entry = conn.read(baseDN);
					log.info("Found domain "+entry.getAttribute("name").getStringValue());
				} catch (Exception e) {
					log.info("Unable to read object "+baseDN);
				}
			}
			searchUserSamAccountName();
		} catch (Exception e) {
			handleException(e, conn);
			throw new InternalErrorException(
					"Cannot connect to active directory", e);
		} finally {
			Watchdog.instance().dontDisturb();
			returnConnection(mainDomain);
		}
	}

	private void searchUserSamAccountName() throws Exception {
		LDAPEntry entry;
		if (loginDN.contains("\\"))
		{
			ExtensibleObject eo = new ExtensibleObject();
			eo.setObjectType(SoffidObjectType.OBJECT_ACCOUNT.getValue());
			eo.setAttribute("objectClass", "user");
			String s = loginDN.substring(loginDN.indexOf('\\')+1);
			entry = searchSamAccount(eo, s);
 			samDomainName = "";
		}
		else {
			String dn = loginDN.toLowerCase().endsWith(baseDN.toLowerCase()) ? loginDN: loginDN+","+baseDN;
			String domain = searchDomainForDN(dn);
			LDAPConnection conn = getConnection(domain);
			try {
				entry = conn.read(dn);
			} finally {
				returnConnection(domain);
			}
			samDomainName = domainHost.get(domain);
		}
		if (entry == null)
			log.warn("Unable to locate administrator account ("+loginDN+","+baseDN+") in LDAP server");
		samAccountName = entry.getAttribute("sAMAccountName").getStringValue();
	}


	protected void returnConnection(String domain) throws InternalErrorException {
		LDAPPool pool = getPool(domain);
		if (pool != null) {
			pool.returnConnection();
		}
	}


	protected LDAPConnection getConnection(String domain) throws Exception {
		LDAPPool pool = getPool(domain);
		if (pool == null) {
			throw new InternalErrorException("Unknown LDAP pool "+domain);
		}
		try {
			LDAPConnection p = pool.getConnection();
			return p;
		} catch (Exception e) {
			if (debugEnabled)
				log.info("Error connecting to "+domain);
			throw e;
		}
	}


	private LDAPPool getPool(String domain) throws InternalErrorException {
		LDAPPool pool = pools.get( Security.getCurrentTenantName()+ "\\"+getCodi()+"/"+domain);
		return pool;
	}

	private void reconfigurePool(String domain, String host) throws InternalErrorException {
		if (debugEnabled)
		{
			log.info("Configuring LDAP pool "+getCodi()+"/"+domain);
			log.info("Server: "+host);
			log.info("Base DN: "+domains.get(domain));
			log.info("User: "+loginDN);
//			log.info("Password: "+ password.getPassword());
		}
		LDAPPool pool = getPool(domain);
		if (pool == null) {
			pool = new LDAPPool();
			pools.put(Security.getCurrentTenantName()+ "\\" + getCodi()+"/"+domain, pool);
		}
		pool.setUseSsl(useSsl );
		pool.setBaseDN( domains.get(domain));
		pool.setLdapHost(host);
		pool.setLdapPort(ldapPort);
		pool.setLdapVersion(ldapVersion);
		pool.setLoginDN(loginDN);
		pool.setPassword(password);
		pool.setAlwaysTrust(trustEverything);
		pool.setFollowReferrals(followReferrals);
		pool.setDebug (debugEnabled);
		pool.setLog(log);
		pool.reconfigure();
		if (getDispatcher().getTimeout() != null)
			pool.setQueryTimeout (getDispatcher().getTimeout());
		List<LDAPPool> children = new LinkedList<LDAPPool>();
		LDAPConnection conn = null;
		pool.setChildPools(null);
	}

	protected void handleException(Exception e, LDAPConnection conn) {
		try {
			if (e instanceof LDAPException &&
					conn != null && 
					((LDAPException) e).getResultCode() == LDAPException.CONNECT_ERROR)
			{
				log.warn("Closing failed connection "+conn.toString());
				conn.disconnect();
			}
		} catch (LDAPException e2) {
			log.warn("Error closing connection ", e);
		}
	}



	private void searchDomains(LDAPConnection conn) throws LDAPException, InternalErrorException {
		String base = baseDN;
		String queryString = "(objectClass=domain)";

		LDAPSearchConstraints constraints = new LDAPSearchConstraints(conn.getConstraints());
		LDAPSearchResults query = conn.search(base,
					LDAPConnection.SCOPE_SUB, queryString, null, false,
					constraints);
		while (query.hasMore()) {
			try {
				LDAPEntry entry = query.next();
				// Ignore embedded domains
				
			} catch (LDAPReferralException e)
			{
				for (String r: e.getReferrals())
				{
					try {
						LDAPUrl url = new LDAPUrl(r);
						String domain = url.getHost().split("\\.")[0];
						String dn = url.getDN();
						if (!domain.endsWith("DnsZones"))
						{
							if (!domains.containsKey(domain.toLowerCase()))
							{
								domains.put(domain.toLowerCase(), dn.toLowerCase());
								domainHost.put(domain.toLowerCase(), url.getHost());
								log.info("Found domain "+dn+" ( "+domain+" ): "+url.getHost());
								reconfigurePool(domain.toLowerCase(), url.getHost());
							}
						}
					} catch (MalformedURLException e1) {
						log.warn("Error decoding "+e.getFailedReferral(), e1);
					}
				}
			}
		}			
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
			boolean mustchange) throws Exception {
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
					mustchange, false);
		}
	}

	private void updateObjectPassword(ExtensibleObject sourceObject,
			String accountName, ExtensibleObject object, Password password,
			boolean mustchange, boolean delegation) throws Exception {
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
						updateObject(accountName, object, sourceObject);
						ldapUser = searchSamAccount(object, samAccount);
					}

					if (ldapUser != null) {
						performPasswordChange(ldapUser, accountName, password,
								mustchange, delegation, false);
					}
					return;
				} catch (LDAPException e) {
					if (e.getResultCode() == LDAPException.UNWILLING_TO_PERFORM
							&& !repeat) {
						updateObject(accountName, object, sourceObject);
						repeat = true;
					} else if (e.getResultCode() == LDAPException.ATTRIBUTE_OR_VALUE_EXISTS) {
						try {
							performPasswordChange(ldapUser, accountName,
									password, mustchange, delegation, true);
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
			boolean replacePassword) throws Exception {
		
		
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
		// Poner el flag de cambiar en el proximo reinicio
		if (mustchange) {
			modList.add(new LDAPModification(LDAPModification.REPLACE,
					new LDAPAttribute("pwdLastSet", "0")));

			status = status | ADS_UF_PASSWORD_EXPIRED;
			status = status & (~ADS_UF_DONT_EXPIRE_PASSWD);
		} else {
			status = status & (~ADS_UF_PASSWORD_EXPIRED);
		}

		if (delegation)
			status |= ADS_UF_NORMAL_ACCOUNT | ADS_UF_DONT_EXPIRE_PASSWD
					| ADS_UF_TRUSTED_FOR_DELEGATION;
		else
			status = status | ADS_UF_NORMAL_ACCOUNT;

		modList.add(new LDAPModification(LDAPModification.REPLACE,
				new LDAPAttribute(USER_ACCOUNT_CONTROL, Integer
						.toString(status))));

		String domain = searchDomainForDN (ldapUser.getDN());
		LDAPConnection conn = getConnection(domain);
		if (conn.isTLS())
		{
			LDAPModification[] mods = new LDAPModification[modList.size()];
			mods = (LDAPModification[]) modList.toArray(mods);
			debugModifications("Modifying password ", ldapUser.getDN(), mods);
			try {
				conn.modify(ldapUser.getDN(), mods);
			} catch (Exception e) {
				handleException(e, conn);
				throw e;
			} finally {
				returnConnection(domain);
			}
		} else {
			updateSamPassword (domain, accountName, password, mustchange);
		}
		log.info("UpdateUserPassword - setting password for user {}",
				accountName, null);
	}

	final SMBClient smbClient = new SMBClient();
	private void updateSamPassword(String domain, String accountName, Password password, boolean mustchange) throws IOException {
		String host = domainHost.get(domain);
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
		    		} finally {
		    			sam.closeHandle(userHandle);
		    		}
		    	}		    	
		    }
		} finally {
			smbConnection.close();
		}

	}


	protected String searchDomainForDN(String dn) {
		if ( ! multiDomain )
			return mainDomain;
		
		long length = 0;
		String selected = mainDomain;
		for (String domain: domains.keySet())
		{
			String base=domains.get(domain);
			if (dn.toLowerCase().endsWith(base.toLowerCase()) && base.length() > length)
			{
				length = base.length();
				selected = domain;
			}
		}
		return selected;
	}


	protected LDAPEntry searchSamAccount(ExtensibleObject object,
			String samAccount) throws Exception {
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
			LDAPEntry entry = findSamObject(objectClass, key, samAccount);
			if (entry == null && "user".equals(objectClass))
			{
				String upn = vom.toSingleString(object.getAttribute("userPrincipalName"));
				if (upn != null)
					entry = findUpnObject (objectClass, samAccount, upn);
			}
			return entry;
		}
		
		for (String att: object.getAttributes())
		{
			try {
				String value = vom.toSingleString(object.getAttribute(att));
				queryString = queryString + "("+att +"="+ escapeLDAPSearchFilter(value) + ")";
			} catch (Exception e) 
			{
			}
		}
		queryString = queryString + ")";

		for (String domain: domains.keySet())
		{
			String base = domains.get(domain);
			if (debugEnabled)
				log.info("Looking for object "+samAccount+": LDAP QUERY="
						+ queryString.toString() + " on " + base);
			LDAPConnection conn = getConnection(domain);
			try {
				LDAPSearchConstraints constraints = new LDAPSearchConstraints(conn.getConstraints());
				LDAPSearchResults query = conn.search(base,
						LDAPConnection.SCOPE_SUB, queryString, null, false,
						constraints);
				while (query.hasMore()) {
					try {
						LDAPEntry entry = query.next();
						return entry;
					} catch (LDAPReferralException e) {
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
		} catch (LDAPException e) {
			if (e.getResultCode() == LDAPException.NO_SUCH_OBJECT)
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
	/**
	 * Funció per obtindre transformar el password a hash per guardar a la bbdd
	 * 
	 * @param password
	 * @return
	 */
	private String getHashPassword(Password password) {
		String hash = null;
		synchronized (digest) {
			hash = passwordPrefix
					+ Base64.encodeBytes(
							digest.digest(password.getPassword().getBytes()),
							Base64.DONT_BREAK_LINES);
		}
		return hash;
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
	 * 
	 * @param usuario
	 *            Informacion del usuario
	 * @throws Exception
	 */
	public void updateObjects(String accountName, String newAccountName, ExtensibleObjects objects,
			ExtensibleObject source) throws Exception {

		for (ExtensibleObject object : objects.getObjects()) {
			Map<String, String> props = getProperties ( object.getObjectType());
			String key = props.get("key");
			if (key == null)
				key = SAM_ACCOUNT_NAME_ATTRIBUTE;
			if (newAccountName != null)
			{
				if ( multiDomain && accountName.contains("\\"))
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
			updateObject(accountName, object, source);
		}
	}

	private String getDN(ExtensibleObject object, String accountName) {
		String dn = (String) object.getAttribute("dn");
		if (dn == null || dn.length() == 0) {
			String name = (String) object.getAttribute("cn");
			if (name == null) name = "";
			else name = name.trim();
			name = "cn=" + name;
			if (object.getAttribute(RELATIVE_DN) != null)
			{
				String domain = getAccountDomain(accountName, dn);
				String base = domains.get(domain);
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
		String domain = searchDomainForDN(dn);
		String base = domains.get(domain);
		if (dn.equalsIgnoreCase(base))
			return;

		boolean found = false;
		LDAPConnection connection = getConnection(domain);
		try {
			connection.read( dn );
			found = true;
		} catch (LDAPReferralException e) {
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
				throw new InternalErrorException("Cannot find nor create object "
						+ dn);
			int i = dn.indexOf(",");
			while (i > 1 && dn.substring(i-1, i).equals("\\"))
				i = dn.indexOf(",", i+1);
			if (i > 0) {
				String parentName = dn.substring(i + 1);
				createParents(parentName);
				LDAPAttributeSet attributeSet = new LDAPAttributeSet();
				int j = dn.substring(i).indexOf("=");
				String name = dn.substring(j, i).replaceAll("\\\\", "");
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
		}
	}

	protected void updateObject(String accountName, ExtensibleObject object,
			ExtensibleObject source) throws Exception {
		String dn = getDN(object, accountName);
		
		String domain = getAccountDomain(accountName, dn);
		String base = domains.get(domain);
		LDAPConnection conn = getConnection(domain);
		Map<String, String> props = getProperties ( object.getObjectType());
		String key = props.get("key");
		if (key == null)
			key = SAM_ACCOUNT_NAME_ATTRIBUTE;

		try {
			
			if (debugEnabled)
				debugObject("Updating object " + accountName, object, "  ");
			LDAPEntry entry = null;
			entry = searchSamAccount(object, accountName);
			if (entry == null) {
				createNewObject(conn, accountName, dn, object, source);
			} else {
				updateExistingObject(conn, entry, accountName, dn, object, source);
			}
		} catch (Exception e) {
			String msg = "updating object : " + accountName;
			log.warn(msg, e);
			handleException(e, conn);
			throw new InternalErrorException(msg, e);
		} finally {
			returnConnection(domain);
		}
	}


	private void updateExistingObject(LDAPConnection conn, LDAPEntry entry, String accountName, String dn,
			ExtensibleObject object, ExtensibleObject source)
			throws InternalErrorException, UnsupportedEncodingException, IOException, Exception, LDAPException {
		if (preUpdate(source, object, entry)) {
			LinkedList<LDAPModification> modList = new LinkedList<LDAPModification>();
			for (String attribute : object.getAttributes()) {
				Object ov = object.getAttribute(attribute);
				if (ov != null && "".equals(ov))
					ov = null;
				if (!"dn".equals(attribute)
						&& !"objectClass".equals(attribute)
						&& !BASE_DN.equals(attribute)
						&& !RELATIVE_DN.equals(attribute)) {
					log.info("Attributo "+attribute+" valor = "+ov+" class "+(ov == null ? "NULL": ov.getClass().toString()));
					String[] value = toStringArray(object.getAttribute(attribute));
					if (value != null && value.length == 0)
					{
						log.info("Caso null array");
						ov = null;
						value = null;
					}
					LDAPAttribute previous = entry.getAttribute(attribute);
					if (ov == null
							&& previous != null) {
						log.info("Caso delete");
						modList.add(new LDAPModification(
								LDAPModification.DELETE,
								new LDAPAttribute(attribute)));
					}
					else if (attribute.equals( SAM_ACCOUNT_NAME_ATTRIBUTE) && ov instanceof String)
					{
						String old = previous == null ? null : 
								previous.getStringValue();
						if ( old == null || ! old.equalsIgnoreCase( (String) ov ))
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
						log.info("Caso add");
						if (ov instanceof byte[]) {
							modList.add(new LDAPModification(
									LDAPModification.ADD,
									new LDAPAttribute(attribute,
											(byte[]) ov)));
						} else {
							modList.add(new LDAPModification(
									LDAPModification.ADD,
									new LDAPAttribute(attribute, value)));
						}
					} else if ((ov != null)
							&& (previous != null)
							&& !"cn".equalsIgnoreCase(attribute)) {
						log.info("Caso update");
						if (value.length != 1 ||
								previous.getStringValueArray().length != 1 ||
								!value[0].equals(previous.getStringValue())) {
							if (ov instanceof byte[])
								modList.add(new LDAPModification(
										LDAPModification.REPLACE,
										new LDAPAttribute(attribute,
												(byte[]) ov)));
							else
								modList.add(new LDAPModification(
										LDAPModification.REPLACE,
										new LDAPAttribute(attribute,
												value)));
						}
					}
				}
			}

			if (modList.size() > 0) {
				// Temporary patch
				String upn = vom.toSingleString(object.getAttribute("userPrincipalName"));
				String objectClass = vom.toSingleString(object
						.getAttribute("objectClass"));
				if (upn != null && objectClass != null)
				{
					LDAPEntry entry2 = findUpnObject (objectClass, accountName, upn);
					if (entry2 != null && ! entry2.getDN().equals(entry.getDN()))
					{
						log.info("Removing userPrincipalName from "+entry2.getDN());
						LDAPModification[] mods2 = new LDAPModification[] {
								new LDAPModification(
										LDAPModification.DELETE,
										new LDAPAttribute("userPrincipalName", upn))
						};
						conn.modify(entry2.getDN(), mods2);
					}
				}
				
				LDAPModification[] mods = new LDAPModification[modList
						.size()];
				mods = (LDAPModification[]) modList.toArray(mods);
				debugModifications("Modifying object ", entry.getDN(),
						mods);
				conn.modify(entry.getDN(), mods);
				postUpdate(source, object, entry);
			}

			if (!entry.getDN().equalsIgnoreCase(dn)
					&& !entry.getDN().contains(",CN=Builtin,")) {
				// Check if must rename
				boolean rename = true;
				ExtensibleObjectMapping mapping = getMapping(object
						.getObjectType());
				if (mapping != null) {
					rename = !"false".equalsIgnoreCase(mapping
							.getProperties().get("rename"));
				}
				if (rename) {
					log.info("Renaming from "+entry.getDN()+" to "+dn);
					int i = dn.indexOf(",");
					if (i > 0) {
						String parentName = dn.substring(i + 1);
						createParents(parentName);

						LDAPEntry oldEntry = searchEntry(dn);
						if (oldEntry != null)
						{
							log.info("Moving away old object "+dn);
							conn.rename(dn, dn.substring(0, i)+" - old "+System.currentTimeMillis(),
									parentName, true);

						}
						entry = conn.read(entry.getDN());
						conn.rename(entry.getDN(), dn.substring(0, i),
								parentName, true);
					}
				}
			}
		}
	}


	private void createNewObject(LDAPConnection conn, String accountName, String dn, ExtensibleObject object,
			ExtensibleObject source)
			throws InternalErrorException, Exception, UnsupportedEncodingException, IOException, LDAPException {
		LDAPEntry entry;
		if (preInsert(source, object)) {
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
				if ("user".equals(object.getObjectType())
						|| "account".equals(object.getObjectType()))
				{
					attributeSet.add(new LDAPAttribute(
							USER_ACCOUNT_CONTROL, Integer
									.toString(ADS_UF_ACCOUNTDISABLE
											+ ADS_UF_NORMAL_ACCOUNT)));
				}
			}

			int i = dn.indexOf(",");
			if (i > 0) {
				String parentName = dn.substring(i + 1);
				createParents(parentName);
			}
			debugModifications("Adding user", dn, attributeSet);
			entry = new LDAPEntry(dn, attributeSet);
			conn.add(entry);
			postInsert(source, object, entry);
			if ((accountName != null)
					&& ("user".equals(object.getObjectType()) || "account"
							.equals(object.getObjectType()))) {
				Password p = getServer().getAccountPassword(
						accountName, getCodi());
				if (p != null) {
					updateObjectPassword(source, accountName, object,
							p, false, false);
				} else {
					p = getServer().generateFakePassword(accountName,
							getCodi());
					updateObjectPassword(source, accountName, object,
							p, true, false);
				}
			}
		}
	}


	private String getAccountDomain(String accountName, String dn) {
		if (accountName == null)
			return searchDomainForDN(dn);
		
		String domain;
		String[] domainSplit = accountName.split("\\\\");
		if (multiDomain && domainSplit.length == 2)
			domain = domainSplit[0].toLowerCase();
		else
			domain = searchDomainForDN(dn);
		return domain;
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

	private ExtensibleObjectMapping getMapping(String objectType) {
		for (ExtensibleObjectMapping map : objectMappings) {
			if (map.getSystemObject().equals(objectType))
				return map;
		}
		return null;
	}

	public void removeObjects(String account, ExtensibleObjects objects,
			ExtensibleObject source) throws Exception {		
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
				if (preDelete(source, entry)) {
					String dn = entry.getDN();
					String domain = searchDomainForDN(dn);
					String base = domains.get(domain);
					LDAPConnection conn = getConnection(domain);
					try {
						log.info("Removing object {}", dn, null);
						List<String> dns = new LinkedList<String>();
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
								// Ignore
							}
						}
						Collections.sort(dns, new Comparator<String>() {
							public int compare(String o1, String o2) {
								return o2.length() - o1.length();
							}
						});
						for (String d: dns)
						{
							log.info("About to remove "+d);
							conn.delete(d);
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

	/**
	 * @param modList
	 * @param entry
	 * @param attribute
	 */
	private void addDeletion(LinkedList<LDAPModification> modList,
			LDAPEntry entry, String attribute) {
		LDAPAttribute att = entry.getAttribute(attribute);
		LDAPModification mod = null;
		if (att != null) {
			mod = new LDAPModification(LDAPModification.DELETE, att);
			modList.add(mod);
		}
	}

	private LDAPEntry findSamAccount(String user) throws Exception {
		return findSamObject("user", SAM_ACCOUNT_NAME_ATTRIBUTE, user);
	}

	private LDAPEntry findSamObject(String objectClass, String key, String value) throws Exception {
		LDAPEntry entry;
		String queryString;
		
		String domainSubtree = baseDN;
		String domain = mainDomain;
		String samAccountName = value;
		
		String[] domainSplit = value.split("\\\\");
		if (multiDomain && domainSplit.length == 2)
		{
			domain = domainSplit[0].toLowerCase();
			domainSubtree = domains.get(domain);
			if (domainSubtree == null)
				throw new InternalErrorException("Searching for object "+value+" on unknown domain "+domainSplit[0]);
			samAccountName = domainSplit[1];
			
		}
		queryString = "(&(objectClass=" + objectClass + ")("+key+"=" + escapeLDAPSearchFilter(samAccountName) + "))";

		
		LDAPConnection conn = getConnection(domain);
		try {
			if (debugEnabled)
				log.info("Searching for object "+queryString+" on domain "+domain+" ("+domainSubtree+")");
			LDAPSearchConstraints constraints = new LDAPSearchConstraints(conn.getConstraints());
			LDAPSearchResults search = conn.search(domainSubtree,
					LDAPConnection.SCOPE_SUB, queryString, null, false,
					constraints);
			while (search.hasMore()) {
				try {
					entry = search.next();
					return entry;
				} catch (LDAPReferralException ldapError) {
					// Ignore
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

	private LDAPEntry findUpnObject(String objectClass, String user, String upn) throws Exception {
		LDAPEntry entry;
		String queryString;
		
		String domainSubtree = baseDN;
		String domain = mainDomain;
		String samAccountName = user;
		
		String[] domainSplit = user.split("\\\\");
		if (multiDomain && domainSplit.length == 2)
		{
			domain = domainSplit[0].toLowerCase();
			domainSubtree = domains.get(domain);
			if (domainSubtree == null)
				throw new InternalErrorException("Searching for object "+user+" on unknown domain "+domainSplit[0]);
			samAccountName = domainSplit[1];
			
		}
		queryString = "(&(objectClass=" + objectClass + ")(userPrincipalName=" + escapeLDAPSearchFilter(upn) + "))";

		
		LDAPConnection conn = getConnection(domain);
		try {
			if (debugEnabled)
				log.info("Searching for object "+queryString+" on domain "+domain+" ("+domainSubtree+")");
			LDAPSearchConstraints constraints = new LDAPSearchConstraints(conn.getConstraints());
			LDAPSearchResults search = conn.search(domainSubtree,
					LDAPConnection.SCOPE_SUB, queryString, null, false,
					constraints);
			while (search.hasMore()) {
				try {
					entry = search.next();
					return entry;
				} catch (LDAPReferralException ldapError) {
					// Ignore
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

	@Override
	public boolean validateUserPassword(String user, Password password)
			throws RemoteException, InternalErrorException {
		String[] ldapHosts = ldapHost.split("[, ]+");
		LDAPConnection conn = null;
		for (String host : ldapHosts) {
			Watchdog.instance().interruptMe(getDispatcher().getTimeout());
			try {

				LDAPEntry entry;
				entry = findSamAccount(user);
				log.info("Creating connection");
				conn = createConnection ();
				
				log.info("Connecting");
				conn.connect(host, ldapPort);

				LDAPConstraints constraints = conn.getConstraints();
				constraints.setReferralFollowing(false);
				conn.setConstraints(constraints);

				log.info("Binding");

				conn.bind(ldapVersion, entry.getDN(), password.getPassword()
						.getBytes("UTF8"));
				conn.disconnect();
				return true;
			} catch (UnsupportedEncodingException e) {
			} catch (Exception e) {
				if (debugEnabled)
					log.info("Error connecting to " + host + " as user " + user+" / "+password.getPassword(), e);
				else
					log.info("Error connecting to " + host + " as user " + user, e);
			} finally {
				Watchdog.instance().dontDisturb();
			}
		}
		return false;
	}

	private LDAPConnection createConnection() throws NoSuchAlgorithmException, KeyManagementException, KeyStoreException, CertificateException, IOException 
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
				else if ("get".equalsIgnoreCase(verb) || "read".equalsIgnoreCase(verb))
				{
					return getLdapObjects (baseDN, command, params);
				}
				else
				{
					return queryLdapObjects (verb, command, params);
				}
			}

		});
	}

	private Collection<Map<String, Object>> queryLdapObjects(String base, String queryString, Map<String, Object> params) throws InternalErrorException {
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
					} 
					catch (LDAPReferralException e)
					{
						// Ignore
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
		String domain = searchDomainForDN(base);
		try {
			LDAPConnection conn = getConnection(domain);
			LDAPPool pool = getPool(domain);
			try
			{
				LinkedList<Map<String, Object>> result = new LinkedList<Map<String,Object>>();
				
				try {
					LDAPEntry entry = conn.read(base);
					result.add( new LDAPExtensibleObject("unknown", entry, pool) );
				} 
				catch (LDAPReferralException e)
				{
					// Ignore
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
				conn.delete(dn);
				return null;
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
		for (String domain: domains.keySet())
		{
			String base = domains.get(domain);
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
									} catch (LDAPReferralException e) {
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

	private String generateAccountName(LDAPEntry entry, ExtensibleObjectMapping mapping, String attName) throws InternalErrorException {
		
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
				boolean found = false;
				String entryDn = entry.getDN().toLowerCase();
				for (String domain: domains.keySet())
				{
					String domainBase = domains.get(domain);
					if (entryDn.substring(entryDn.indexOf(",dc=")+1).equalsIgnoreCase(domainBase))
					{
						accountName = domain+"\\"+accountName;
						found = true;
						break;
					}
				}
				if (! found)
				{
					log.warn("DN: "+entryDn);
					for (String domain: domains.keySet())
					{
						String domainBase = domains.get(domain);
						log.warn("Base: "+domainBase);
					}
					throw new InternalErrorException("Unable to guess domain for "+entryDn);
				}
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
		for (String domain: domains.keySet())
		{
			String domainBase = domains.get(domain);
			if (entryDn.substring(entryDn.indexOf(",dc=")+1).equalsIgnoreCase(domainBase))
			{
				return domain;
			}
		}
		log.warn("DN: "+entryDn);
		for (String domain: domains.keySet())
		{
			String domainBase = domains.get(domain);
			log.warn("Base: "+domainBase);
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
		
		for (String domain: domains.keySet())
		{
			String base = domains.get(domain);
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
									} catch (LDAPReferralException e) {
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
//		log.info("Updating account :"+account.toString());
//		log.info("         user :"+userData.toString());
		UserExtensibleObject source = new UserExtensibleObject(account,
				userData, getServer());
		ExtensibleObjects objects = objectTranslator.generateObjects(source);

		Watchdog.instance().interruptMe(getDispatcher().getTimeout());
		try {
			updateObjects(getAccountName(account), userName, objects, source);
			for (ExtensibleObject object : objects.getObjects()) {
				if ("user".equals(object.getObjectType())
						|| "account".equals(object.getObjectType())) {
					updateUserStatus(userName, object, !account.isDisabled(), new UserExtensibleObject(account, userData, getServer()));
					updateUserGroups(userName, object, !account.isDisabled());
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
	 * @throws Exception
	 */
	private void updateUserStatus(String userName, ExtensibleObject object, boolean enable, ExtensibleObject soffidObject)
			throws Exception {
		LDAPEntry entry = searchSamAccount(object, userName);

		if (entry != null) {
			LDAPModification modif = null;

			// Update 'userAccountControl' attribute
			int status = 0;
			LDAPAttribute att = entry.getAttribute(USER_ACCOUNT_CONTROL);

			if (att != null)
				status = Integer.decode(att.getStringValue()).intValue();

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
				if (e.getResultCode() == LDAPException.UNWILLING_TO_PERFORM && enable && entry.getAttribute("unicodePwd") == null)
				{
					Password password = getServer().getOrGenerateUserPassword(userName, getDispatcher().getCodi());
				
					if (conn.isTLS())
					{
						byte b[] = encodePassword(password);
						LDAPModification modif2 = new LDAPModification(LDAPModification.ADD, new LDAPAttribute("unicodePwd", b));
						LDAPModification[] mods = new LDAPModification[] { modif2, modif };
						debugModifications("Updating user data ", entry.getDN(), mods);
						conn.modify(entry.getDN(), mods);
					} else {
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
	}

	/**
	 * @param userName
	 * @param userData
	 * @param searchSamAccount
	 * @throws Exception
	 * @throws UnknownGroupException
	 */
	private void updateUserGroups(String userName, ExtensibleObject object, boolean enabled)
			throws Exception {
		// Aquí llegamos en usuarios nuevos y existentes ACTIVOS
		// Gestionamos la membresía del usuario a roles y grupos
		// en el atributo memberOf del usuario lo tenemos
		LDAPEntry userEntry = searchSamAccount(object, userName);
		if (userEntry == null)
			return;
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
			for (RolGrant grant : getServer().getAccountRoles(userName, dispatcher)) {
				if (!groups.contains(grant.getRolName()))
					groups.add(grant.getRolName());
			}
			for (Grup grup : getServer().getUserGroups(userName, dispatcher)) {
				if (!groups.contains(grup.getCodi()))
					groups.add(grup.getCodi());
			}
			for (Iterator<String> it = groups.iterator(); it.hasNext();) {
				String groupCode = it.next();
				log.info("User {} should belong to [{}]", userName, groupCode);
				if (!h_soffidGroups.containsKey(groupCode.toLowerCase()))
				{
					try {
						addGroupMember(groupCode, userName, userEntry);
					} catch (Exception e) {
						lastException = e;
						log.warn("Error adding group membership", e);
					}
				}
				else
					h_soffidGroups.remove(groupCode.toLowerCase());
			}
		}

		// Esborram dels grups excedents
		for (Iterator it = h_soffidGroups.entrySet().iterator(); it.hasNext();) {
			Map.Entry<String, String> entry = (Map.Entry<String, String>) it
					.next();
			try {
				removeGroupMember(entry.getValue(), userName, userEntry);
			} catch (Exception e) {
				lastException = e;
				log.warn("Error removing group membership", e);
			}
		}
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

		LDAPEntry groupEntry = searchSamAccount(eo.getObjects().get(0),
				group);

		// No existing group
		if (groupEntry == null) {
			if (soffidGroup != null)
				updateGroup(group, soffidGroup);
			if (soffidRole != null)
				updateRole(soffidRole);
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
			updateObjects(oldAccountName, accountName, objects, sourceObject);
			for (ExtensibleObject object : objects.getObjects()) {
				if ("user".equals(object.getObjectType())
						|| "account".equals(object.getObjectType())) {
					updateUserStatus(accountName, object, !account.isDisabled(), new AccountExtensibleObject(account, getServer()));
					updateUserGroups(accountName, object, ! account.isDisabled());
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
		if (account == null || account.getStatus() == AccountStatus.REMOVED)
		{
			realRemove = true;
			account = new Account();
			account.setName(userName);
			account.setDescription(userName);
			account.setDisabled(true);
			account.setDispatcher(getDispatcher().getCodi());
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
					updateUserStatus(userName, object, false, sourceObject);
					updateUserGroups(userName, object, false);
				}
				removeObjects(userName, objects, sourceObject);
			} else {
				for (ExtensibleObject object : objects.getObjects()) {
					if (searchSamAccount(object, userName) != null)
					{
						updateObject(userName, object, sourceObject);
						updateUserStatus(userName, object, false, sourceObject);
						updateUserGroups(userName, object, false);
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
					mustchange);
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
			RoleExtensibleObject sourceObject = new RoleExtensibleObject(rol,
					getServer());
			ExtensibleObjects objects = objectTranslator
					.generateObjects(sourceObject);
			Watchdog.instance().interruptMe(getDispatcher().getTimeout());
			try {
				updateObjects(rol.getNom(), rol.getNom(), objects, sourceObject);
			} catch (InternalErrorException e) {
				throw e;
			} catch (Exception e) {
				throw new InternalErrorException(e.getMessage(), e);
			} finally {
				Watchdog.instance().dontDisturb();
			}

		}
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
			removeObjects(rolName, objects, sourceObject);
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
			updateObjects(key, key, objects, sourceObject);
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
			removeObjects(key, objects, sourceObject);
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
			String uid;
			String principal;
			if (server.contains("/")) {
				principal = server;
				uid = server.replace('/', '_');
			} else {
				uid = "SEYCON_" + server;
				if (uid.indexOf('.') > 0)
					uid = uid.substring(0, uid.indexOf('.'));
				if (uid.length() > 20)
					uid = uid.substring(0, 20);
				principal = "SEYCON/" + server;
			}

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

					LDAPModification[] mods = new LDAPModification[] {
							new LDAPModification(LDAPModification.REPLACE,
									atributo)
							 ,
							new LDAPModification(LDAPModification.REPLACE,
									new LDAPAttribute(USER_ACCOUNT_CONTROL,
											Integer.toString(status))) 
							};
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
					} catch (LDAPReferralException e) {
//						log.info("Cannot follow referral: "+e.toString());
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
	public Collection<AuthoritativeChange> getChanges(String nextChange)
			throws InternalErrorException {
		Collection<AuthoritativeChange> changes = new LinkedList<AuthoritativeChange>();
		Watchdog.instance().interruptMe(getDispatcher().getLongTimeout());
		try {
			log.info("Getting changes from " + nextChange);
			if (searches == null)
			{
				searches = new Stack<CustomizableActiveDirectoryAgent.LdapSearch>();
				for (String domain: domains.keySet())
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
						parseUser(changes, object);
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


	private void parseUser(Collection<AuthoritativeChange> changes, ExtensibleObject object)
			throws InternalErrorException {
		Usuari user = vom.parseUsuari(object);
		if (user != null) {
			AuthoritativeChange change = new AuthoritativeChange();

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

			changes.add(change);
		}
	}

	private void parseGroup(Collection<AuthoritativeChange> changes, ExtensibleObject object)
			throws InternalErrorException {
		Grup group = vom.parseGroup(object);
		if (group != null) {
			AuthoritativeChange change = new AuthoritativeChange();

			AuthoritativeChangeIdentifier id = new AuthoritativeChangeIdentifier();
			change.setId(id);
			id.setChangeId(null);
			id.setEmployeeId("group:"+group.getCodi());
			id.setDate(new Date());

			change.setGroup(group);
			changes.add(change);
		}
	}

	protected void parseCustomObject(Collection<AuthoritativeChange> changes, ExtensibleObject object) throws InternalErrorException {
	
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
			String[] v = ldapAttribute.getStringValueArray();
			for (int j = 0; j < v.length; j++) {
				if (j > 0)
					b.append(", ");
				b.append(v[j]);
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

	protected void debugObject(String msg, Map<String, Object> obj,
			String indent) {
		if (debugEnabled) {
			if (indent == null)
				indent = "";
			if (msg != null)
				log.info(indent + msg);
			for (String attribute : obj.keySet()) {
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
			String baseDN = domains.get(domain);
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
			for (String att : dummySystemObject.getAttributes()) {
				String value = vom.toSingleString(dummySystemObject
						.getAttribute(att));
				if ("baseDN".equalsIgnoreCase(att) ||
						RELATIVE_DN.equalsIgnoreCase(att)) {
				} else if (!"dn".equalsIgnoreCase(att)) {
					if (value != null) {
						sb.append("(").append(att).append("=")
								.append(escapeLDAPSearchFilter(value))
								.append(")");
						any = true;
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


	@Override
	public Collection<LogEntry> getLogFromDate(Date From) throws RemoteException, InternalErrorException {
		return new LinkedList<LogEntry>();
	}

	public boolean supportsRename ()
	{
		return true;
	}

}

