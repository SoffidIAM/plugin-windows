package com.soffid.iam.sync.agent;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.rmi.RemoteException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPControl;
import com.novell.ldap.LDAPDN;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPJSSESecureSocketFactory;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPReferralException;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.LDAPSearchResults;
import com.novell.ldap.controls.LDAPPagedResultsControl;
import com.novell.ldap.controls.LDAPPagedResultsResponse;
import com.soffid.iam.api.Group;

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
		implements ExtensibleObjectMgr, UserMgr, ReconcileMgr2, RoleMgr, GroupMgr,
		KerberosAgent, AuthoritativeIdentitySource2
{

	LDAPPool pool = null;
	
	static HashMap<String,LDAPPool> pools = new HashMap<String, LDAPPool>();
	
	private static final String SAM_ACCOUNT_NAME_ATTRIBUTE = "sAMAccountName";

	final static int ADS_UF_SCRIPT = 0x1;

	final static int ADS_UF_ACCOUNTDISABLE = 0x2;

	final static int ADS_UF_HOMEDIR_REQUIRED = 0x8;

	final static int ADS_UF_LOCKOUT = 0x10;

	final static int ADS_UF_PASSWD_NOTREQD = 0x20;

	final static int ADS_UF_PASSWD_CANT_CHANGE = 0x40;

	final static int ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED = 0x80;

	final static int ADS_UF_TEMP_DUPLICATE_ACCOUNT = 0x100;

	final static int ADS_UF_NORMAL_ACCOUNT = 0x200;

	final static int ADS_UF_INTERDOMAIN_TRUST_ACCOUNT = 0x800;

	final static int ADS_UF_WORKSTATION_TRUST_ACCOUNT = 0x1000;

	final static int ADS_UF_SERVER_TRUST_ACCOUNT = 0x2000;

	final static int ADS_UF_DONT_EXPIRE_PASSWD = 0x10000;

	final static int ADS_UF_MNS_LOGON_ACCOUNT = 0x20000;

	final static int ADS_UF_SMARTCARD_REQUIRED = 0x40000;

	final static int ADS_UF_TRUSTED_FOR_DELEGATION = 0x80000;

	final static int ADS_UF_NOT_DELEGATED = 0x100000;

	final static int ADS_UF_USE_DES_KEY_ONLY = 0x200000;

	final static int ADS_UF_DONT_REQUIRE_PREAUTH = 0x400000;

	final static int ADS_UF_PASSWORD_EXPIRED = 0x800000;

	final static int ADS_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 0x1000000;

	ValueObjectMapper vom = new ValueObjectMapper();

	ObjectTranslator objectTranslator = null;

	private static final long serialVersionUID = 1L;

	// constante de máximo número de miembros de un grupo (evitar timeout)
	private static final int MAX_GROUP_MEMBERS = 5000;

	/** Puerto de conexion LDAP * */
	int ldapPort = LDAPConnection.DEFAULT_SSL_PORT;
	/** Version del servidor LDAP */
	int ldapVersion = LDAPConnection.LDAP_V3;
	/** Usuario root de conexión LDAP */
	String loginDN;
	/** Password del usuario administrador cn=root,dc=caib,dc=es */
	Password password;
	/** HOST donde se aloja LDAP */
	String ldapHost;
	/** ofuscador de claves SHA */
	MessageDigest digest;

	String usersContext;
	String rolesContext;

	// Vamos a er la hora en la que empieza y la hora en la que acaba.
	long inicio;
	long fin;
	int usuarios = 0;

	private String passwordAttribute;

	private String hashType;

	private String passwordPrefix;

	private Collection<ExtensibleObjectMapping> objectMappings;

	private String baseDN;

	private boolean debugEnabled;
	// --------------------------------------------------------------

	/**
	 * Constructor
	 * 
	 * @param params
	 *          Parámetros de configuración: <li>0 = código de usuario LDAP</li>
	 *          <li>1 = contraseña de acceso LDAP</li> <li>2 = host</li> <li>3 =
	 *          Nombre del attribute password</li> <li>4 = Algoritmo de hash</li>
	 */
	public CustomizableActiveDirectoryAgent () throws RemoteException
	{
	}

	@Override
	public void init () throws InternalErrorException
	{
		log.info("Starting Customizable Active Directory agent on {}",
				getDispatcher().getCodi(), null);
		loginDN = getDispatcher().getParam2();
		password = Password.decode(getDispatcher().getParam3());
		// password = params[1];
		ldapHost = getDispatcher().getParam0();
		baseDN = getDispatcher().getParam1();
		clustered = ("cluster".equalsIgnoreCase(getDispatcher().getParam4()));
		setquota = ("quota".equalsIgnoreCase(getDispatcher().getParam5()));
		allowedDrives = getDispatcher().getParam6();

		debugEnabled = "true".equals(getDispatcher().getParam7());

		log.debug("Started ActiveDirectoryAgent improved user=" + loginDN
				+ " pass=" + password + "(" + password.getPassword() + ")", null, null);
		try
		{
			javaDisk = new bubu.util.javadisk();
		}
		catch (Throwable e)
		{
//			e.printStackTrace();
		}
		pool = pools.get(getCodi());
		if ( pool == null)
		{
			pool = new LDAPPool();
			pools.put(getCodi(), pool);
		}
		pool.setBaseDN(baseDN);
		pool.setLdapHost(ldapHost);
		pool.setLdapPort(ldapPort);
		pool.setLdapVersion(ldapVersion);
		pool.setLoginDN(loginDN);
		pool.setPassword(password);
		Watchdog.instance().interruptMe(getDispatcher().getTimeout());
		try {
			pool.getConnection();
		} catch (Exception e) {
			throw new InternalErrorException("Cannot connect to active directory", e);
		} finally {
			Watchdog.instance().dontDisturb();
			pool.returnConnection();
		}
	}

	/**
	 * Actualiza la contraseña del usuario. Genera la ofuscación SHA-1 y la asigna
	 * al atributo userpassword de la clase inetOrgPerson
	 * 
	 * @param accountName
	 * @throws Exception 
	 */
	@SuppressWarnings ({ "unchecked", "rawtypes" })
	public void updatePassword (String accountName, ExtensibleObjects objects,
			Password password, boolean mustchange) throws Exception
	{
		for (ExtensibleObject object : objects.getObjects())
		{
			updateObjectPassword(accountName, object, password, mustchange, false);
		}
	}

	private void updateObjectPassword (String accountName,
			ExtensibleObject object, Password password, boolean mustchange,
			boolean delegation) throws Exception
	{
		LDAPEntry ldapUser = null;
		LDAPAttribute atributo;
		String samAccount = accountName;
		if (samAccount != null)
		{
			boolean repeat = false;
			do
			{
				try
				{
					if (samAccount != null)
						ldapUser = searchSamAccount(object, samAccount);

					if (ldapUser == null)
					{
						updateObject(accountName, object);
						ldapUser = searchSamAccount(object, samAccount);
					}

					if (ldapUser != null)
					{
						performPasswordChange(ldapUser, accountName, password, mustchange,
								delegation, false);
					}
					return;
				}
				catch (LDAPException e)
				{
					if (e.getResultCode() == LDAPException.UNWILLING_TO_PERFORM
							&& !repeat)
					{
						updateObject(accountName, object);
						repeat = true;
					}
					else if (e.getResultCode() == LDAPException.ATTRIBUTE_OR_VALUE_EXISTS)
					{
						try
						{
							performPasswordChange(ldapUser, accountName, password,
									mustchange, delegation, true);
						}
						catch (Exception e2)
						{
							String msg = "UpdateUserPassword('" + accountName + "')";
							log.warn(msg+"(First attempt)", e);
							log.warn(msg+"(Second attempt)", e2);
							throw new InternalErrorException(msg + e2.getMessage(), e2);
						}
					}
					else
					{
						String msg = "UpdateUserPassword('" + accountName + "')";
						log.warn(msg, e);
						throw new InternalErrorException(msg + e.getMessage(), e);
					}
				}
				catch (Exception e)
				{
					String msg =
							"Error UpdateUserPassword('" + accountName + "'). ["
									+ e.getMessage() + "]";
					log.warn(msg, e);
					throw new InternalErrorException(msg, e);
				}
			} while (repeat);
		}
	}

	private void performPasswordChange (LDAPEntry ldapUser, String accountName,
			Password password, boolean mustchange, boolean delegation,
			boolean replacePassword) throws Exception
	{
		ArrayList<LDAPModification> modList = new ArrayList<LDAPModification>();
		LDAPAttribute atributo;
		byte b[] = encodePassword(password);
		atributo = new LDAPAttribute("unicodePwd", b);

		if ((ldapUser.getAttribute("unicodePwd") == null) && !replacePassword)
			modList.add(new LDAPModification(LDAPModification.ADD, atributo));
		else
			modList.add(new LDAPModification(LDAPModification.REPLACE, atributo));
		// Unlock account
		LDAPAttribute att = ldapUser.getAttribute("userAccountControl");
		int status = 0;
		if (att != null)
			status = Integer.decode(att.getStringValue()).intValue();
		// Quitar el bloqueo
		status = status & (~ADS_UF_LOCKOUT);
		// Poner el flag de cambiar en el proximo reinicio
		if (mustchange)
		{
			modList.add(new LDAPModification(LDAPModification.REPLACE,
					new LDAPAttribute("pwdLastSet", "0")));

			status = status | ADS_UF_PASSWORD_EXPIRED;
			status = status & (~ADS_UF_DONT_EXPIRE_PASSWD);
		}
		else
		{
			status = status & (~ADS_UF_PASSWORD_EXPIRED);
		}

		if (delegation)
			status |=
					ADS_UF_NORMAL_ACCOUNT | ADS_UF_DONT_EXPIRE_PASSWD
							| ADS_UF_TRUSTED_FOR_DELEGATION;
		else
			status = status | ADS_UF_NORMAL_ACCOUNT;

		modList.add(new LDAPModification(LDAPModification.REPLACE,
				new LDAPAttribute("userAccountControl", Integer.toString(status))));

		LDAPModification[] mods = new LDAPModification[modList.size()];
		mods = (LDAPModification[]) modList.toArray(mods);
		debugModifications("Modifying password ", ldapUser.getDN(), mods);
		try {
			pool.getConnection().modify(ldapUser.getDN(), mods);
		} finally {
			pool.returnConnection();
		}
		log.info("UpdateUserPassword - setting password for user {}", accountName,
				null);
	}

	private LDAPEntry
			searchSamAccount (ExtensibleObject object, String samAccount)
					throws Exception
	{
		String base = baseDN;
		String objectClass = vom.toSingleString(object.getAttribute("objectClass"));
		String queryString =
				"(&(objectClass=" + objectClass + ")(sAMAccountName=" + escapeLDAPSearchFilter(samAccount)
						+ "))";
		if (debugEnabled)
			log.info("Looking for objects: LDAP QUERY=" + queryString.toString()
					+ " on " + base);
		try {
			LDAPSearchResults query =
					pool.getConnection().search(base, LDAPConnection.SCOPE_SUB, queryString,
							null, false);
			while (query.hasMore())
			{
				LDAPEntry entry = query.next();
				return entry;
			}
			
			return null;
		} finally {
			pool.returnConnection();
		}
		
	}

	/**
	 * Busca los datos de un usuario en el directorio LDAP
	 * 
	 * @param user
	 *          codigo del usuario
	 * @return LDAPEntry entrada del directorio LDAP
	 * @throws Exception 
	 */
	private LDAPEntry searchEntry (String dn) throws Exception
	{
		try
		{
			return pool.getConnection().read(dn);
		}
		catch (LDAPException e)
		{
			if (e.getResultCode() == LDAPException.NO_SUCH_OBJECT)
				return null;
			String msg =
					"buscarUsuario ('" + dn + "'). Error al buscar el usuario. ["
							+ e.getMessage() + "]";
			log.warn(msg, e);
			throw new InternalErrorException(msg, e);
		} finally {
			pool.returnConnection();
		}
	}

	/**
	 * Funció per obtindre transformar el password a hash per guardar a la bbdd
	 * 
	 * @param password
	 * @return
	 */
	private String getHashPassword (Password password)
	{
		String hash = null;
		synchronized (digest)
		{
			hash =
					passwordPrefix
							+ Base64.encodeBytes(
									digest.digest(password.getPassword().getBytes()),
									Base64.DONT_BREAK_LINES);
		}
		return hash;
	}

	private String[] toStringArray (Object obj)
	{
		if (obj == null)
			return null;
		else if (obj instanceof String[])
		{
			return (String[]) obj;
		}
		else if (obj instanceof Object[])
		{
			return vom.toStringArray((Object[]) obj);
		}
		else
		{
			return new String[] { vom.toString(obj) };
		}
	}

	/**
	 * Añade los datos de un usuario al directorio LDAP
	 * 
	 * @param accountName
	 * 
	 * @param usuario
	 *          Informacion del usuario
	 * @throws Exception 
	 */
	public void updateObjects (String accountName, ExtensibleObjects objects)
			throws Exception
	{

		for (ExtensibleObject object : objects.getObjects())
		{
			updateObject(accountName, object);
		}
	}

	private String getDN (ExtensibleObject object)
	{
		String dn = (String) object.getAttribute("dn");
		if (dn == null || dn.length() == 0)
		{
			return "cn=" + object.getAttribute("cn") + ","
					+ object.getAttribute("baseDn");
		}
		else
			return dn;
	}

	private void createParents (String dn) throws Exception
	{
		if (dn.equals(baseDN))
			return;

		try
		{
			pool.getConnection().read(dn);
		}
		catch (LDAPException e)
		{
			if (e.getResultCode() == LDAPException.NO_SUCH_OBJECT)
			{
				int i = dn.indexOf(",");
				if (i > 0)
				{
					String parentName = dn.substring(i + 1);
					createParents(parentName);
					LDAPAttributeSet attributeSet = new LDAPAttributeSet();
					int j = dn.substring(i).indexOf("=");
					String name = dn.substring(j, i);
					if (dn.toLowerCase().startsWith("ou="))
					{
						attributeSet.add(new LDAPAttribute("objectclass",
								"organizationalUnit"));
						attributeSet.add(new LDAPAttribute("ou", name));
					}
					else
					{
						throw new InternalErrorException("Unable to create object " + dn);
					}
					LDAPEntry entry = new LDAPEntry(dn, attributeSet);
					try {
						pool.getConnection().add(entry);
					} finally {
						pool.returnConnection();
					}
				}
			}
			else
				throw e;
		} finally {
			pool.returnConnection();
		}
	}

	private void updateObject (String accountName, ExtensibleObject object)
			throws Exception
	{
		LDAPConnection conn = pool.getConnection();
		try
		{
			log.info("Updating object {}", accountName, null);
			LDAPEntry entry = null;
			entry = searchSamAccount(object, accountName);
			if (entry == null)
			{
				LDAPAttributeSet attributeSet = new LDAPAttributeSet();
				for (String attribute : object.getAttributes())
				{
					String values[] = toStringArray(object.getAttribute(attribute));
					if (values != null && !"dn".equals(attribute)
							&& !"baseDn".equals(attribute)
							&& !SAM_ACCOUNT_NAME_ATTRIBUTE.equals(attribute))
					{
						attributeSet.add(new LDAPAttribute(attribute, values));
					}
				}
				attributeSet.add(new LDAPAttribute(SAM_ACCOUNT_NAME_ATTRIBUTE,
						accountName));

				if (object.getAttribute("userAccountControl") == null)
				{
					if ("user".equals(object.getObjectType())
							|| "account".equals(object.getObjectType()))
						attributeSet.add(new LDAPAttribute("userAccountControl", Integer
								.toString(ADS_UF_ACCOUNTDISABLE + ADS_UF_NORMAL_ACCOUNT)));
				}

				String dn = getDN(object);
				int i = dn.indexOf(",");
				if (i > 0)
				{
					String parentName = dn.substring(i + 1);
					createParents(parentName);
				}
				debugModifications("Adding user", dn, attributeSet);
				entry = new LDAPEntry(dn, attributeSet);
				conn.add(entry);
				if ((accountName != null)
						&& ("user".equals(object.getObjectType()) || "account"
								.equals(object.getObjectType())))
				{
					Password p = getServer().getAccountPassword(accountName, getCodi());
					if (p != null)
					{
						updateObjectPassword(accountName, object, p, false, false);
					}
					else
					{
						p = getServer().generateFakePassword(accountName, getCodi());
						updateObjectPassword(accountName, object, p, true, false);
					}
				}
			}
			else
			{
				LinkedList<LDAPModification> modList =
						new LinkedList<LDAPModification>();
				for (String attribute : object.getAttributes())
				{
					if (!"dn".equals(attribute) && !"objectClass".equals(attribute)
							&& !"baseDn".equals(attribute) && !SAM_ACCOUNT_NAME_ATTRIBUTE.equals(attribute))
					{
						String[] value = toStringArray(object.getAttribute(attribute));
						if (value == null && entry.getAttribute(attribute) != null)
						{
							modList.add(new LDAPModification(LDAPModification.DELETE,
									new LDAPAttribute(attribute)));
						}
						else if (value != null && entry.getAttribute(attribute) == null)
						{
							modList.add(new LDAPModification(LDAPModification.ADD,
									new LDAPAttribute(attribute, value)));
						}
						else if ((value != null) && (entry.getAttribute(attribute) != null)
								&& !"cn".equalsIgnoreCase(attribute))
						{
							if (value.length != 1
									|| !value[0].equals(entry.getAttribute(attribute)
											.getStringValue()))
							{
								modList.add(new LDAPModification(LDAPModification.REPLACE,
										new LDAPAttribute(attribute, value)));
							}
						}
					}
				}

				if (modList.size() > 0)
				{
					LDAPModification[] mods = new LDAPModification[modList.size()];
					mods = (LDAPModification[]) modList.toArray(mods);
					debugModifications("Modifying object ", entry.getDN(), mods);
					conn.modify(entry.getDN(), mods);
				}

				String dn = getDN(object);

				if (!entry.getDN().equalsIgnoreCase(dn) && ! entry.getDN().contains(",CN=Builtin,"))
				{
					// Check if must rename
					boolean rename = true;
					ExtensibleObjectMapping mapping = getMapping ( object.getObjectType());
					if (mapping != null)
					{
						rename = ! "false".equalsIgnoreCase(mapping.getProperties().get("rename"));
					}
					if (rename)
					{
						int i = dn.indexOf(",");
						if (i > 0)
						{
							String parentName = dn.substring(i + 1);
							createParents(parentName);
							
							entry = conn.read(entry.getDN());
							conn.rename(entry.getDN(), dn.substring(0, i),
									parentName, true);
						}
					}
				}
			}
		}
		catch (Exception e)
		{
			String msg = "updating object : " + accountName;
			log.warn(msg, e);
			throw new InternalErrorException(msg, e);
		} finally {
			pool.returnConnection();
		}
	}

	private ExtensibleObjectMapping getMapping(String objectType) {
		for (ExtensibleObjectMapping map: objectMappings)
		{
			if ( map.getSystemObject().equals(objectType))
				return map;
		}
		return null;
	}

	public void removeObjects (String account, ExtensibleObjects objects)
			throws Exception
	{
		LDAPConnection conn = pool.getConnection();
		try
		{
			for (ExtensibleObject object : objects.getObjects())
			{
				LDAPEntry entry;
				try
				{
					entry = searchSamAccount(object, account);
				}
				catch (Exception e1)
				{
					String msg = "Error searching for account " + account;
					log.warn(msg, e1);
					throw new InternalErrorException(msg, e1);
				}
				if (entry != null)
				{
					String dn = entry.getDN();
					try
					{
						if (!"user".equals(object.getObjectType())
								&& !"account".equals(object.getObjectType()))
						{
							log.info("Removing object {}", dn, null);
							conn.delete(dn);
						}
						else
						{
							LinkedList<LDAPModification> modList =
									new LinkedList<LDAPModification>();
	
							addDeletion(modList, entry, "profilePath");
							addDeletion(modList, entry, "homeDrive");
							addDeletion(modList, entry, "homeDirectory");
	
							int status = 0;
							LDAPAttribute att = entry.getAttribute("userAccountControl");
							if (att != null)
								status = Integer.decode(att.getStringValue()).intValue();
	
							status = status | ADS_UF_ACCOUNTDISABLE;
	
							modList.add(new LDAPModification(LDAPModification.REPLACE,
									new LDAPAttribute("userAccountControl", Integer
											.toString(status))));
	
							LDAPModification[] mods = new LDAPModification[modList.size()];
							mods = (LDAPModification[]) modList.toArray(mods);
							debugModifications("Disabling object ", dn, mods);
							conn.modify(dn, mods);
						}
	
					}
					catch (Exception e)
					{
						String msg = "updating object : " + dn;
						log.warn(msg, e);
						throw new InternalErrorException(msg, e);
					}
				}
			}
		} finally {
			pool.returnConnection();
		}
	}

	/**
	 * @param modList
	 * @param entry
	 * @param attribute
	 */
	private void addDeletion (LinkedList<LDAPModification> modList,
			LDAPEntry entry, String attribute)
	{
		LDAPAttribute att = entry.getAttribute(attribute);
		LDAPModification mod = null;
		if (att != null)
		{
			mod = new LDAPModification(LDAPModification.DELETE, att);
			modList.add(mod);
		}
	}

	private LDAPEntry findSamAccount(String user) throws Exception {
		LDAPEntry entry;
		String searchFilter = "(&(objectClass=user)(sAMAccountName=" + escapeLDAPSearchFilter(user)
				+ "))";
		LDAPConnection conn = pool.getConnection();
		try
		{
			LDAPSearchResults search = conn.search(baseDN,
					LDAPConnection.SCOPE_SUB, searchFilter, null, false);
			if (search.hasMore()) {
				try {
					entry = search.next();
				} catch (LDAPReferralException ldapError) {
					System.out.println("User " + user + "is not an AD user.");
					entry = null;
				}
			} else {
				entry = null;
			}
			return entry;
			
			
		} finally {
			pool.returnConnection();
		}
	}

	@Override
	public boolean validateUserPassword (String user, Password password)
			throws RemoteException, InternalErrorException
	{
		String[] ldapHosts = ldapHost.split("[, ]+");
		LDAPConnection conn = null;
		for (String host: ldapHosts)
		{
			Watchdog.instance().interruptMe(getDispatcher().getTimeout());
			try
			{
	
				LDAPEntry entry;
				entry = findSamAccount(user);
				conn = new LDAPConnection(new LDAPJSSESecureSocketFactory());
				conn.connect(host, ldapPort);
				conn.bind(ldapVersion, entry.getDN(), password
						.getPassword().getBytes("UTF8"));
				conn.disconnect();
				return true;
			}
			catch (UnsupportedEncodingException e)
			{
			}
			catch (Exception e)
			{
				log.info("Error connecting to "+host+" as user " + user , e);
			}
			finally {
				Watchdog.instance().dontDisturb();
			}
		}
		return false;
	}


	public void configureMappings (Collection<ExtensibleObjectMapping> objects)
			throws RemoteException, InternalErrorException
	{
		this.objectMappings = objects;
//		for (ExtensibleObjectMapping m: objectMappings)
//		{
//			if (SoffidObjectType.OBJECT_ACCOUNT.equals(m.getSoffidObject()) ||
//					SoffidObjectType.OBJECT_USER.equals(m.getSoffidObject()))
//			{
//				AttributeMapping am = new AttributeMapping("accountName", SAM_ACCOUNT_NAME_ATTRIBUTE, AttributeDirection.OUTPUT, m.getId());
//				m.getAttributes().add(am);
//			}
//			if (SoffidObjectType.OBJECT_GROUP.equals(m.getSoffidObject()))
//			{
//				AttributeMapping am = new AttributeMapping("name", SAM_ACCOUNT_NAME_ATTRIBUTE, AttributeDirection.OUTPUT, m.getId());
//				m.getAttributes().add(am);
//			}
//			if (SoffidObjectType.OBJECT_ROLE.equals(m.getSoffidObject()))
//			{
//				AttributeMapping am = new AttributeMapping("name", SAM_ACCOUNT_NAME_ATTRIBUTE, AttributeDirection.OUTPUT, m.getId());
//				m.getAttributes().add(am);
//			}
//		}
		objectTranslator =
				new ObjectTranslator(getDispatcher(), getServer(), objectMappings);
		objectTranslator.setObjectFinder(new ExtensibleObjectFinder() {
			
			public ExtensibleObject find(ExtensibleObject pattern) throws Exception {
				String samAccount = (String) pattern.getAttribute(SAM_ACCOUNT_NAME_ATTRIBUTE);
				Watchdog.instance().interruptMe(getDispatcher().getTimeout());
				try {
					LDAPEntry entry = searchSamAccount(pattern, samAccount);
					if (entry != null)
					{
						for (ObjectMapping m: objectMappings)
						{
							if (m.getSystemObject().equals(pattern.getObjectType()))
								return parseEntry(entry, m);
						}
					}
					return null;
				} finally {
					Watchdog.instance().dontDisturb();
				}
			}
		});
	}

	AttributeMapping findAttribute (ExtensibleObjectMapping objectMapping,
			String attribute)
	{
		for (AttributeMapping attMapping : objectMapping.getAttributes())
		{
			if (attMapping.getSystemAttribute().equals(attribute)
					&& (attMapping.getDirection().equals(AttributeDirection.OUTPUT) || attMapping
							.getDirection().equals(AttributeDirection.INPUTOUTPUT)))
			{
				return attMapping;
			}
		}
		return null;
	}

	LinkedList<String> getSoffidAccounts (SoffidObjectType type)
			throws Exception
	{
		LDAPConnection conn = pool.getConnection();
		try {
			LinkedList<String> accounts = new LinkedList<String>();
	
			ExtensibleObject dummySoffidObj = new ExtensibleObject();
			dummySoffidObj.setObjectType(type.getValue());
	
			for (ExtensibleObjectMapping mapping : objectMappings)
			{
				if (mapping.getSoffidObject().equals(type))
				{
					ExtensibleObject dummySystemObject =
							objectTranslator.generateObject(dummySoffidObj, mapping, true);
	
					StringBuffer sb = new StringBuffer();
					sb.append("(&");
					boolean any = false;
					String base = baseDN;
					for (String att : dummySystemObject.getAttributes())
					{
						String value =
								vom.toSingleString(dummySystemObject.getAttribute(att));
						if ((value != null) && !"dn".equals(att) && !"baseDn".equals(att))
						{
							sb.append("(").append(att).append("=").append(value).append(")");
							any = true;
						}
					}
					sb.append("(!(objectClass=computer)))");
					if (any && base != null)
					{
						LDAPSearchConstraints oldConst =
								conn.getSearchConstraints();	// Save search constraints
						LDAPPagedResultsControl pageResult =
								new LDAPPagedResultsControl(conn
										.getSearchConstraints().getMaxResults(), false);
	
						do
						{
							LDAPSearchConstraints constraints =
									conn.getSearchConstraints();
							constraints.setControls(pageResult);
							conn.setConstraints(constraints);
	
							if (debugEnabled)
								log.info("Looking for objects: LDAP QUERY=" + sb.toString()
										+ " on " + base);
							LDAPSearchResults search =
									conn.search(base, LDAPConnection.SCOPE_SUB,
											sb.toString(), null, false);
							while (search.hasMore())
							{
								LDAPEntry entry = search.next();
	
								accounts.add(entry.getAttribute(SAM_ACCOUNT_NAME_ATTRIBUTE)
										.getStringValue());
							}
	
							LDAPControl responseControls[] = search.getResponseControls();
							pageResult.setCookie(null); // in case no cookie is returned we need
																					// to step out of do..while
	
							if (responseControls != null)
							{
								for (int i = 0; i < responseControls.length; i++)
								{
									if (responseControls[i] instanceof LDAPPagedResultsResponse)
									{
										LDAPPagedResultsResponse response =
												(LDAPPagedResultsResponse) responseControls[i];
										pageResult.setCookie(response.getCookie());
									}
								}
							}
						} while (pageResult.getCookie() != null);
	
						conn.setConstraints(oldConst);
					}
				}
			}
			return accounts;
		} finally {
			pool.returnConnection();
		}
	}

	private String removeIncompleteComponentsFromBase (String base)
	{
		if (base == null)
			return null;
		else if (base.endsWith("="))
		{
			base = base.substring(0, base.lastIndexOf(",")).trim();
		}
		if (base.endsWith(","))
			base = base.substring(0, base.length() - 1);
		return base;
	}

	public List<String> getAccountsList () throws RemoteException,
			InternalErrorException
	{
		Set<String> accounts = new HashSet<String>();
		Watchdog.instance().interruptMe(getDispatcher().getLongTimeout());
		try
		{
			accounts.addAll(getSoffidAccounts(SoffidObjectType.OBJECT_USER));
			accounts.addAll(getSoffidAccounts(SoffidObjectType.OBJECT_ACCOUNT));
		}
		catch (Exception e)
		{
			throw new InternalErrorException("Error getting accounts list", e);
		} finally {
			Watchdog.instance().dontDisturb();
		}
		return new LinkedList<String>(accounts);
	}

	public ExtensibleObject parseEntry (LDAPEntry entry, ObjectMapping mapping)
	{
		ExtensibleObject eo = new ExtensibleObject();
		eo.setAttribute("dn", entry.getDN());
		eo.setObjectType(mapping.getSystemObject());
		for (Object obj : entry.getAttributeSet())
		{
			LDAPAttribute att = (LDAPAttribute) obj;
			if (att.getStringValueArray().length == 1)
				eo.setAttribute(att.getName(), att.getStringValue());
			else
				eo.setAttribute(att.getName(), att.getStringValueArray());
		}
		return eo;
	}

	public Usuari getUserInfo (String userAccount) throws RemoteException,
			InternalErrorException
	{
		ExtensibleObject eo;
		Watchdog.instance().interruptMe(getDispatcher().getTimeout());
		try
		{
			eo = findExtensibleUser(userAccount);
		}
		catch (InternalErrorException e)
		{
			throw e;
		}
		catch (Exception e)
		{
			throw new InternalErrorException(e.getMessage());
		} finally {
			Watchdog.instance().dontDisturb();
		}

		if (eo == null)
			return null;
		ExtensibleObjects parsed = objectTranslator.parseInputObjects(eo);
		for (ExtensibleObject peo : parsed.getObjects())
		{
			Usuari usuari = vom.parseUsuari(peo);
			if (usuari != null)
				return usuari;
			Account account = vom.parseAccount(peo);
			if (account != null)
			{
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

	private ExtensibleObject findExtensibleUser (String userAccount)
			throws Exception
	{
		return findUserByExample(userAccount);
	}

	private ExtensibleObject findUserByExample (String userAccount)
			throws Exception
	{
		ExtensibleObject account = new ExtensibleObject();
		account.setObjectType(SoffidObjectType.OBJECT_ACCOUNT.getValue());
		account.setAttribute("accountName", userAccount);
		// For each suitable mappping
		for (ExtensibleObjectMapping objectMapping : objectMappings)
		{
			if (objectMapping.getSoffidObject().getValue()
					.equals(account.getObjectType()))
			{
				// Generate system objects from source user
				ExtensibleObject systemObject =
						objectTranslator.generateObject(account, objectMapping, true);

				LDAPEntry result = searchSamAccount(systemObject, userAccount);
				if (result != null)
				{
					return parseEntry(result, objectMapping);
				}
			}
		}
		return null;
	}

	public List<String> getRolesList () throws RemoteException,
			InternalErrorException
	{
		Set<String> roles = new HashSet<String>();
		Watchdog.instance().interruptMe(getDispatcher().getLongTimeout());
		try
		{
			roles.addAll(getSoffidRoles(SoffidObjectType.OBJECT_GROUP));
			roles.addAll(getSoffidRoles(SoffidObjectType.OBJECT_ROLE));
		}
		catch (LDAPException e)
		{
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
	LinkedList<String> getSoffidRoles (SoffidObjectType objectGroup)
			throws Exception
	{

		LDAPConnection conn = pool.getConnection();
		try
		{
			LinkedList<String> roles = new LinkedList<String>();
	
			ExtensibleObject dummySoffidObj = new ExtensibleObject();
			dummySoffidObj.setObjectType(objectGroup.getValue());
	
			for (ExtensibleObjectMapping mapping : objectMappings)
			{
				if (mapping.getSoffidObject().equals(objectGroup))
				{
					ExtensibleObject dummySystemObject =
							objectTranslator.generateObject(dummySoffidObj, mapping, true);
	
					StringBuffer sb = new StringBuffer();
					sb.append("(&");
					boolean any = false;
					String base = baseDN;
					for (String att : dummySystemObject.getAttributes())
					{
						String value =
								vom.toSingleString(dummySystemObject.getAttribute(att));
						if ((value != null) && !"dn".equals(att) && !"baseDn".equals(att))
						{
							sb.append("(").append(att).append("=").append(escapeLDAPSearchFilter(value)).append(")");
							any = true;
						}
					}
					sb.append(")");
					if (any && base != null)
					{
						LDAPSearchConstraints oldConst =
								conn.getSearchConstraints();	// Save search constraints
						LDAPPagedResultsControl pageResult =
								new LDAPPagedResultsControl(conn
										.getSearchConstraints().getMaxResults(), false);
	
						do
						{
							LDAPSearchConstraints constraints =
									conn.getSearchConstraints();
							constraints.setControls(pageResult);
							conn.setConstraints(constraints);
	
							if (debugEnabled)
								log.info("Looking for objects: LDAP QUERY=" + sb.toString()
										+ " on " + base);
							LDAPSearchResults search =
									conn.search(base, LDAPConnection.SCOPE_SUB,
											sb.toString(), null, false);
							while (search.hasMore())
							{
								LDAPEntry entry = search.next();
	
								roles.add(entry.getAttribute(SAM_ACCOUNT_NAME_ATTRIBUTE).getStringValue());
							}
	
							LDAPControl responseControls[] = search.getResponseControls();
							pageResult.setCookie(null); // in case no cookie is returned we need
																					// to step out of do..while
	
							if (responseControls != null)
							{
								for (int i = 0; i < responseControls.length; i++)
								{
									if (responseControls[i] instanceof LDAPPagedResultsResponse)
									{
										LDAPPagedResultsResponse response =
												(LDAPPagedResultsResponse) responseControls[i];
										pageResult.setCookie(response.getCookie());
									}
								}
							}
						} while (pageResult.getCookie() != null);
	
						conn.setConstraints(oldConst);
					}
				}
			}
			return roles;
		} finally {
			pool.returnConnection();
		}
	}

	public Rol getRoleFullInfo (String roleName) throws RemoteException,
			InternalErrorException
	{
		ExtensibleObject rolObject = new ExtensibleObject();
		rolObject.setObjectType(SoffidObjectType.OBJECT_ROLE.getValue());
		rolObject.setAttribute("name", roleName);
		rolObject.setAttribute("system", getDispatcher().getCodi());

		// Generate a dummy object to perform query
		ExtensibleObjects systemObjects =
				objectTranslator.generateObjects(rolObject);
		for (ExtensibleObject systemObject : systemObjects.getObjects())
		{
			LDAPEntry entry = null;
			Watchdog.instance().interruptMe(getDispatcher().getTimeout());
			try
			{
				entry = searchSamAccount(systemObject, roleName);
			}
			catch (LDAPException e)
			{
				throw new InternalErrorException(e.getMessage(), e);
			}
			catch (InternalErrorException e)
			{
				throw e;
			} catch (Exception e) {
				throw new InternalErrorException(e.getMessage(), e);
			} finally {
				Watchdog.instance().dontDisturb();
			}
			if (entry != null)
			{
				for (ExtensibleObjectMapping objectMapping : objectMappings)
				{
					if (objectMapping.getSoffidObject().getValue()
							.equals(rolObject.getObjectType()))
					{
						ExtensibleObject eo = parseEntry(entry, objectMapping);
						ExtensibleObject parsed =
								objectTranslator.parseInputObject(eo, objectMapping);
						if (parsed != null)
						{
							Rol rol = vom.parseRol(parsed);
							if (rol != null)
							{
								if (rol.getDescripcio() == null)
									rol.setDescripcio(entry.getAttribute("CN").getStringValue());
								rol.setNom(roleName);

								return rol;
							}
						}
					}
				}
			}
		}
		return null;
	}

	public List<Rol> getAccountRoles (String userAccount) throws RemoteException,
			InternalErrorException
	{
		Rol userRole; // User role
		LinkedList<Rol> rolesList = new LinkedList<Rol>(); // User roles
		LDAPEntry userEntry;	 // User LDAP entry
		Watchdog.instance().interruptMe(getDispatcher().getTimeout());
		try
		{
			ExtensibleObject eo = findExtensibleUser(userAccount);
			LDAPAttribute memberofattr; // User LDAP groups
			String userGroups[]; // User group array

			Object memberofattr1 = eo.getAttribute("dn");
			userEntry = searchEntry(memberofattr1.toString());
			memberofattr = userEntry.getAttribute("memberOf");
			userGroups =
					(memberofattr == null ? new String[] {} : memberofattr
							.getStringValueArray());

			// Process the user groups
			for (int i = 0; i < userGroups.length; i++)
			{
				String group =
						searchEntry(userGroups[i]).getAttribute(SAM_ACCOUNT_NAME_ATTRIBUTE)
								.getStringValue();

				userRole = getRoleFullInfo(group);

				log.info("User {} belongs to [{}]", userAccount, userRole.getNom());
				rolesList.add(userRole);
			}
		}
		catch (LDAPException e)
		{
			throw new InternalErrorException(e.getMessage());
		}
		catch (InternalErrorException e)
		{
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException(e.getMessage(), e);
		} finally {
			Watchdog.instance().dontDisturb();
		}

		return rolesList;
	}

	public void updateUser (String userName, Usuari userData)
			throws RemoteException, InternalErrorException
	{
		Account account = new Account();
		account.setName(userName);
		account.setDescription(userData.getFullName());
		account.setDisabled(userData.getActiu());
		account.setDispatcher(getDispatcher().getCodi());
		ExtensibleObjects objects =
				objectTranslator.generateObjects(new UserExtensibleObject(account,
						userData, getServer()));

		Watchdog.instance().interruptMe(getDispatcher().getTimeout());
		try
		{
			updateObjects(userName, objects);
			for (ExtensibleObject object : objects.getObjects())
			{
				if ("user".equals(object.getObjectType())
						|| "account".equals(object.getObjectType()))
				{
					updateUserData(userName, object);
					updateUserGroups(userName, object);
				}
			}
		}
		catch (LDAPException e)
		{
			throw new InternalErrorException("Error updating user", e);
		}
		catch (UnknownUserException e)
		{
			throw new InternalErrorException("Error updating user", e);
		}
		catch (UnknownRoleException e)
		{
			throw new InternalErrorException("Error updating user", e);
		}
		catch (InternalErrorException e)
		{
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
	 * @throws Exception 
	 */
	private void updateUserData (String userName, ExtensibleObject object)
			throws Exception
	{
		LDAPEntry entry = searchSamAccount(object, userName);

		if (entry != null)
		{
			LDAPModification modif = null;

			// Update 'userAccountControl' attribute
			int status = 0;
			LDAPAttribute att = entry.getAttribute("userAccountControl");

			if (att != null)
				status = Integer.decode(att.getStringValue()).intValue();

			// Remove 'disable'
			status = status & (~ADS_UF_ACCOUNTDISABLE);
			// Remove 'lockout'
			status = status & (~ADS_UF_LOCKOUT);
			// Remove flag to never password expires
			// status = status & (~ADS_UF_DONT_EXPIRE_PASSWD);
			// Enable normal account status
			status = status | ADS_UF_NORMAL_ACCOUNT;

			modif =
					new LDAPModification(LDAPModification.REPLACE, new LDAPAttribute(
							"userAccountControl", Integer.toString(status)));
			debugModifications("Updating user data ", entry.getDN(),
					new LDAPModification[] { modif });
			LDAPConnection conn = pool.getConnection();
			try {
				conn.modify(entry.getDN(), modif);
			} finally {
				pool.returnConnection();
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
	private void updateUserGroups (String userName, ExtensibleObject object)
			throws Exception
	{
		// Aquí llegamos en usuarios nuevos y existentes ACTIVOS
		// Gestionamos la membresía del usuario a roles y grupos
		// en el atributo memberOf del usuario lo tenemos
		LDAPEntry userEntry = searchSamAccount(object, userName);
		LDAPAttribute memberofattr = userEntry.getAttribute("memberOf");
		String dispatcher = getCodi();
		String soffidGroups[] =
				((memberofattr == null) ? new String[] {} : memberofattr
						.getStringValueArray());
		HashMap<String, String> h_soffidGroups = new HashMap<String, String>(); // Soffid
																																						// groups
		for (int i = 0; i < soffidGroups.length; i++)
		{
			LDAPEntry groupEntry = searchEntry(soffidGroups[i]);
			String groupCN =
					groupEntry.getAttribute(SAM_ACCOUNT_NAME_ATTRIBUTE).getStringValue();
			log.info("User {} belongs to [{}]", userName, groupCN);
			h_soffidGroups.put(groupCN.toLowerCase(), groupEntry.getDN());
		}

		// roles seycon: rolesUsuario - grupos seycon: grupsUsuari
		// Get roles and groups of users
		HashSet<String> groups = new HashSet<String>();
		for (RolGrant grant : getServer().getAccountRoles(userName, dispatcher))
		{
			if (!groups.contains(grant.getRolName()))
				groups.add(grant.getRolName());
		}
		for (Grup grup : getServer().getUserGroups(userName, dispatcher))
		{
			if (!groups.contains(grup.getCodi()))
				groups.add(grup.getCodi());
		}

		for (Iterator<String> it = groups.iterator(); it.hasNext();)
		{
			String groupCode = it.next();
			log.info("User {} should belong to [{}]", userName, groupCode);
			if (!h_soffidGroups.containsKey(groupCode.toLowerCase()))
				addGroupMember(groupCode, userName, userEntry);

			else
				h_soffidGroups.remove(groupCode.toLowerCase());
		}
		// Esborram dels grups excedents
		for (Iterator it = h_soffidGroups.entrySet().iterator(); it.hasNext();)
		{
			Map.Entry<String, String> entry = (Map.Entry<String, String>) it.next();
			removeGroupMember(entry.getValue(), userName, userEntry);
		}
	}

	/**
	 * @param grup
	 * @param userName
	 * @param userEntry
	 * @throws Exception 
	 * @throws UnknownGroupException
	 */
	private void removeGroupMember (String groupDN, String userName,
			LDAPEntry userEntry) throws Exception
	{
		log.info("Removing user {} from group {}", userName, groupDN);
		LDAPConnection c = pool.getConnection();
		try
		{
			LDAPEntry groupEntry = searchEntry(groupDN);

			// No existing group
			if (groupEntry == null)
			{
				return;
			}
			else
			{
				LDAPModification ldapModification =
						new LDAPModification(LDAPModification.DELETE, new LDAPAttribute(
								"member", userEntry.getDN()));
				debugModifications("Removing group member ", groupEntry.getDN(),
						new LDAPModification[] { ldapModification });
				c.modify(groupEntry.getDN(), ldapModification);
			}
		} finally {
			pool.returnConnection();
		}
	}

	private void addGroupMember (String group, String user, LDAPEntry userEntry)
			throws Exception
	{
		Grup soffidGroup = null;
		Rol soffidRole = null;
		ExtensibleObjects eo = null;
		log.info("Adding user {} to group {}", user, group);
		LDAPConnection lc = pool.getConnection();
		try
		{
			try
			{
				soffidGroup =
						getServer().getGroupInfo(group, getDispatcher().getCodi());
				eo =
						objectTranslator.generateObjects(new GroupExtensibleObject(
								soffidGroup, getDispatcher().getCodi(), getServer()));
			}

			catch (UnknownGroupException e)
			{
				soffidRole = getServer().getRoleInfo(group, getDispatcher().getCodi());
				eo =
						objectTranslator.generateObjects(new RoleExtensibleObject(
								soffidRole, getServer()));
			}

			if (eo.getObjects().isEmpty())
				return;
			
			LDAPEntry groupEntry = searchSamAccount(eo.getObjects().get(0), group);

			// No existing group
			if (groupEntry == null)
			{
				if (soffidGroup != null)
					updateGroup(group, soffidGroup);
				if (soffidRole != null)
					updateRole(soffidRole);
				groupEntry = searchSamAccount(eo.getObjects().get(0), group);
			}
			LDAPModification ldapModification =
					new LDAPModification(LDAPModification.ADD, new LDAPAttribute(
							"member", userEntry.getDN()));
			debugModifications("Adding group member ", groupEntry.getDN(),
					new LDAPModification[] { ldapModification });
			lc.modify(groupEntry.getDN(), ldapModification);
			log.info("Added", null, null);
		} finally {
			pool.returnConnection();
		}
	}

	public void updateUser (String accountName, String description)
			throws RemoteException, InternalErrorException
	{
		Account account = new Account();
		account.setName(accountName);
		account.setDescription(description);
		account.setDisabled(false);
		account.setDispatcher(getDispatcher().getCodi());
		ExtensibleObjects objects =
				objectTranslator.generateObjects(new AccountExtensibleObject(account,
						getServer()));

		Watchdog.instance().interruptMe(getDispatcher().getTimeout());
		try
		{
			updateObjects(accountName, objects);
			for (ExtensibleObject object : objects.getObjects())
			{
				if ("user".equals(object.getObjectType())
						|| "account".equals(object.getObjectType()))
				{
					updateUserData(accountName, object);
					updateUserGroups(accountName, object);
				}
			}
		}
		catch (LDAPException e)
		{
			throw new InternalErrorException(e.getMessage());
		}
		catch (UnknownUserException e)
		{
			throw new InternalErrorException(e.getMessage());
		}
		catch (UnknownRoleException e)
		{
			throw new InternalErrorException(e.getMessage());
		}
		catch (InternalErrorException e)
		{
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException(e.getMessage(), e);
		} finally {
			Watchdog.instance().dontDisturb();
		}

	}

	public void removeUser (String userName) throws RemoteException,
			InternalErrorException
	{

		Account account = new Account();
		account.setName(userName);
		account.setDescription(userName);
		account.setDisabled(true);
		account.setDispatcher(getDispatcher().getCodi());
		ExtensibleObjects objects;

		try
		{
			Usuari user =
					getServer().getUserInfo(userName, getDispatcher().getCodi());
			objects =
					objectTranslator.generateObjects(new UserExtensibleObject(account,
							user, getServer()));
		}
		catch (UnknownUserException e)
		{
			objects =
					objectTranslator.generateObjects(new AccountExtensibleObject(account,
							getServer()));
		}
		Watchdog.instance().interruptMe(getDispatcher().getTimeout());
		try {
			removeObjects(userName, objects);
		}
		catch (InternalErrorException e)
		{
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException(e.getMessage(), e);
		} finally {
			Watchdog.instance().dontDisturb();
		}

	}

	public void updateUserPassword (String userName, Usuari userData,
			Password password, boolean mustchange) throws RemoteException,
			InternalErrorException
	{
		Account account = new Account();
		account.setName(userName);
		account.setDescription((userData != null) ? userData.getFullName()
				: userName);
		account.setDisabled(false);
		account.setDispatcher(getDispatcher().getCodi());

		ExtensibleObjects objects = null;
		if (userData != null)
			objects =
					objectTranslator.generateObjects(new UserExtensibleObject(account,
							userData, getServer()));

		else
			objects =
					objectTranslator.generateObjects(new AccountExtensibleObject(account,
							getServer()));

		Watchdog.instance().interruptMe(getDispatcher().getTimeout());
		try {
			updatePassword(userName, objects, password, mustchange);
		}
		catch (InternalErrorException e)
		{
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException(e.getMessage(), e);
		} finally {
			Watchdog.instance().dontDisturb();
		}

	}

	public void updateRole (Rol rol) throws RemoteException,
			InternalErrorException
	{
		if (rol.getBaseDeDades().equals(getDispatcher().getCodi()))
		{
			ExtensibleObjects objects =
					objectTranslator.generateObjects(new RoleExtensibleObject(rol,
							getServer()));
			Watchdog.instance().interruptMe(getDispatcher().getTimeout());
			try {
				updateObjects(rol.getNom(), objects);
			}
			catch (InternalErrorException e)
			{
				throw e;
			} catch (Exception e) {
				throw new InternalErrorException(e.getMessage(), e);
			} finally {
				Watchdog.instance().dontDisturb();
			}

		}
	}

	public void removeRole (String rolName, String dispatcher)
			throws RemoteException, InternalErrorException
	{
		Rol rol = new Rol();
		rol.setNom(rolName);
		rol.setBaseDeDades(dispatcher);
		ExtensibleObjects objects =
				objectTranslator.generateObjects(new RoleExtensibleObject(rol,
						getServer()));
		Watchdog.instance().interruptMe(getDispatcher().getTimeout());
		try {
			removeObjects(rolName, objects);
		}
		catch (InternalErrorException e)
		{
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException(e.getMessage(), e);
		} finally {
			Watchdog.instance().dontDisturb();
		}
	}

	public void updateGroup (String key, Grup grup) throws RemoteException,
			InternalErrorException
	{
		ExtensibleObjects objects =
				objectTranslator.generateObjects(new GroupExtensibleObject(grup,
						getDispatcher().getCodi(), getServer()));
		Watchdog.instance().interruptMe(getDispatcher().getTimeout());
		try {
			updateObjects(key, objects);
		}
		catch (InternalErrorException e)
		{
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException(e.getMessage(), e);
		} finally {
			Watchdog.instance().dontDisturb();
		}
	}

	public void removeGroup (String key) throws RemoteException,
			InternalErrorException
	{
		Grup grup = new Grup();
		grup.setCodi(key);
		ExtensibleObjects objects =
				objectTranslator.generateObjects(new GroupExtensibleObject(grup,
						getDispatcher().getCodi(), getServer()));
		Watchdog.instance().interruptMe(getDispatcher().getTimeout());
		try {
			removeObjects(key, objects);
		}
		catch (InternalErrorException e)
		{
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException(e.getMessage(), e);
		} finally {
			Watchdog.instance().dontDisturb();
		}
	}

	public KerberosPrincipalInfo createServerPrincipal (String server)
			throws InternalErrorException
	{
		try
		{
			String uid;
			String principal;
			if (server.contains("/"))
			{
				principal = server;
				uid = server.replace('/', '_');
			}
			else
			{
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

			ExtensibleObjects ldapObjects = objectTranslator.generateObjects(object);

			for (ExtensibleObject ldapObject : ldapObjects.getObjects())
			{
				LDAPEntry entry = searchSamAccount(ldapObject, uid);
				LDAPConnection lc = pool.getConnection();
				try
				{
					if (entry == null)
					{
						ldapObject.setAttribute(SAM_ACCOUNT_NAME_ATTRIBUTE, uid);
						// New user object
						LDAPAttributeSet attributeSet = new LDAPAttributeSet();
						for (String attribute : ldapObject.getAttributes())
						{
							String values[] =
									toStringArray(ldapObject.getAttribute(attribute));
							if (values != null && !"dn".equals(attribute)
									&& !"baseDn".equals(attribute))
							{
								log.info("Adding attribute {}={}", attribute, values);
								attributeSet.add(new LDAPAttribute(attribute, values));
							}
						}

						// Bind to be run as a service
						attributeSet.add(new LDAPAttribute("userAccountControl", Integer
								.toString(ADS_UF_ACCOUNTDISABLE | ADS_UF_NORMAL_ACCOUNT
										| ADS_UF_TRUSTED_FOR_DELEGATION)));

						attributeSet.add(new LDAPAttribute("servicePrincipalName",
								principal));
						log.info("Adding attribute {}={}", "servicePrincipalName",
								principal);

						String dn = getDN(ldapObject);
						entry = new LDAPEntry(dn, attributeSet);
						log.warn("Creating {}", dn, null);
						lc.add(entry);
					}

					// Asign the password
					byte v[] = encodePassword(result.getPassword());
					LDAPAttribute atributo = new LDAPAttribute("unicodePwd", v);
					int status =
							ADS_UF_NORMAL_ACCOUNT | ADS_UF_DONT_EXPIRE_PASSWD
									| ADS_UF_TRUSTED_FOR_DELEGATION;

					LDAPModification[] mods =
							new LDAPModification[] {
									new LDAPModification(LDAPModification.REPLACE, atributo),
									new LDAPModification(LDAPModification.REPLACE,
											new LDAPAttribute("userAccountControl",
													Integer.toString(status))) };
					debugModifications("Removing group member ", entry.getDN(), mods);
					lc.modify(entry.getDN(), mods);

					return result;
				} finally {
					pool.returnConnection();
				}
			}
			throw new InternalErrorException("No account mapping found for kerberos account");
		}
		catch (LDAPException e)
		{
			log.warn("Error creating service principal", e);
			throw new InternalErrorException(e.toString(), e);
		}
		catch (IOException e)
		{
			log.warn("Error creating service principal", e);
			throw new InternalErrorException(e.toString(), e);
		}
		catch (TimedOutException e)
		{
			log.warn("Error creating service principal", e);
			throw new InternalErrorException(e.toString(), e);
		}
		catch (InternalErrorException e)
		{
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException(e.getMessage(), e);
		}
	}

	private byte[] encodePassword (Password p) throws InternalErrorException
	{
		try
		{
			return ("\"" + p.getPassword() + "\"").getBytes("UTF-16LE");
		}
		catch (UnsupportedEncodingException e)
		{
			throw new InternalErrorException("Error generating password: "
					+ e.toString(), e);
		}
	}

	public String getRealmName ()
	{
		String parts[] = LDAPDN.explodeDN(baseDN, true);
		StringBuffer realm = new StringBuffer();
		for (int i = 0; i < parts.length; i++)
		{
			if (i > 0)
				realm.append(".");
			realm.append(parts[i].toUpperCase());
		}
		return realm.toString();
	}

	public String[] getRealmServers () throws InternalErrorException
	{
		try
		{
			InetAddress[] addrs = InetAddress.getAllByName(getRealmName());
			String result[] = new String[addrs.length];
			for (int i = 0; i < result.length; i++)
			{
				result[i] = addrs[i].getHostAddress();
			}
			return result;
		}
		catch (UnknownHostException e)
		{
			throw new InternalErrorException("Unknown host " + getRealmName(), e);
		}
	}

	HashMap<String, String> pendingChanges = new HashMap<String, String>();

	LinkedList<ExtensibleObject> getLdapObjects (SoffidObjectType type,
			String nextChange, int count) throws Exception
	{

		ExtensibleObject dummySoffidObj = new ExtensibleObject();
		LinkedList<ExtensibleObject> objects = new LinkedList<ExtensibleObject>();
		dummySoffidObj.setObjectType(type.getValue());

		for (ExtensibleObjectMapping mapping : objectMappings)
		{
			if (mapping.getSoffidObject().equals(type))
			{
				ExtensibleObject dummySystemObject =
						objectTranslator.generateObject(dummySoffidObj, mapping, true);

				StringBuffer sb = new StringBuffer();
				sb.append("(&");
				boolean any = false;
				String base = baseDN;
				for (String att : dummySystemObject.getAttributes())
				{
					String value =
							vom.toSingleString(dummySystemObject.getAttribute(att));
					if ("baseDN".equalsIgnoreCase(att))
					{
						base = value;
					}
					else if (!"dn".equalsIgnoreCase(att))
					{
						if (value != null)
						{
							sb.append("(").append(att).append("=").append(escapeLDAPSearchFilter(value)).append(")");
							any = true;
						}
					}
				}

				if (nextChange != null)
					sb.append("(uSNChanged>=").append(escapeLDAPSearchFilter(nextChange)).append(")");
				sb.append(")");

				if (debugEnabled)
					log.info("Looking for objects: LDAP QUERY=" + sb.toString() + " on "
							+ base);

				if (any && base != null)
				{
					LDAPConnection lc = pool.getConnection();
					try {
						LDAPSearchConstraints oldConst = lc.getSearchConstraints();	// Save
																																				// search
																																				// constraints
						LDAPPagedResultsControl pageResult =
								new LDAPPagedResultsControl(count, false);
	
						do
						{
							LDAPSearchConstraints constraints = lc.getSearchConstraints();
							constraints.setControls(pageResult);
							constraints.setMaxResults(0);
							lc.setConstraints(constraints);
	
							LDAPSearchResults searchResults =
									lc.search(base, LDAPConnection.SCOPE_SUB, sb.toString(), null,
											false);
	
							// Process results
							while (searchResults.hasMore())
							{
								boolean add = false;
								LDAPEntry entry;
								try
								{
									entry = searchResults.next();
								}
								catch (LDAPException e)
								{
									if (e.getResultCode() == LDAPException.NO_SUCH_OBJECT)
										break;
									else
										throw e;
								}
								String lastChange = pendingChanges.get(entry.getDN());
								LDAPAttribute lastChangeAttribute =
										entry.getAttribute("uSNChanged");
	
								if (lastChangeAttribute != null)
								{
									if (lastChange == null)
										add = true;
									else if (!lastChange.equals(lastChangeAttribute
											.getStringValue()))
										add = true;
								}
	
								if (add)
								{
									ExtensibleObject eo = parseEntry(entry, mapping);
									objects.add(eo);
									Long changeId =
											Long.decode(lastChangeAttribute.getStringValue());
									pendingChanges.put(entry.getDN(), changeId.toString());
									if (lastUploadedChange == null
											|| lastUploadedChange.longValue() < changeId)
										lastUploadedChange = changeId;
									if (count-- == 0)
										break;
								}
							}
	
							LDAPControl responseControls[] =
									searchResults.getResponseControls();
							pageResult.setCookie(null); // in case no cookie is returned we need
																					// to step out of do..while
	
							if (responseControls != null)
							{
								for (int i = 0; i < responseControls.length; i++)
								{
									if (responseControls[i] instanceof LDAPPagedResultsResponse)
									{
										LDAPPagedResultsResponse response =
												(LDAPPagedResultsResponse) responseControls[i];
										pageResult.setCookie(response.getCookie());
									}
								}
							}
						} while (pageResult.getCookie() != null && count > 0);
						lc.getSearchConstraints().setControls(new LDAPControl[0]);
					} catch (Exception e) {
						throw new InternalErrorException(e.getMessage(), e);
					} finally {
						pool.returnConnection();
					}
				}
			}
		}
		return objects;
	}

	private boolean firstChange = true;
	private Long lastUploadedChange = null;

	public Collection<AuthoritativeChange> getChanges (String nextChange)
			throws InternalErrorException
	{
		Collection<AuthoritativeChange> changes =
				new LinkedList<AuthoritativeChange>();
		Watchdog.instance().interruptMe(getDispatcher().getLongTimeout());
		try
		{
			if (firstChange)
				pendingChanges = new HashMap<String, String>();

			LinkedList<ExtensibleObject> objects =
					getLdapObjects(SoffidObjectType.OBJECT_USER, nextChange, 150);
			if (objects.isEmpty())
			{
				firstChange = true;
				pendingChanges = new HashMap<String, String>();
			}
			else
			{
				firstChange = false;
			}

			for (ExtensibleObject ldapObject : objects)
			{
				ExtensibleObjects parsedObjects =
						objectTranslator.parseInputObjects(ldapObject);
				for (ExtensibleObject object : parsedObjects.getObjects())
				{
					Usuari user = vom.parseUsuari(object);
					if (user != null)
					{
						AuthoritativeChange change = new AuthoritativeChange();

						AuthoritativeChangeIdentifier id =
								new AuthoritativeChangeIdentifier();
						change.setId(id);
						id.setChangeId(null);
						id.setEmployeeId(user.getCodi());
						id.setDate(new Date());

						change.setUser(user);

						Object groups = object.getAttribute("secondaryGroups");
						if (groups instanceof Collection)
						{
							Set<String> groupsList = new HashSet<String>();
							for (Object group : (Collection<Object>) object)
							{
								if (group instanceof String)
								{
									groupsList.add((String) group);
								}
								else if (group instanceof ExtensibleObject)
								{
									Object name =
											(String) ((ExtensibleObject) group).getAttribute("name");
									if (name != null)
										groupsList.add(name.toString());
								}
								else if (group instanceof Group)
								{
									groupsList.add(((Group) group).getName());
								}
								else if (group instanceof Grup)
								{
									groupsList.add(((Grup) group).getCodi());
								}
							}
							change.setGroups(groupsList);
						}

						Object attributes = object.getAttribute("attributes");
						if (attributes instanceof Map)
						{
							Map<String, Object> attributesMap = new HashMap<String, Object>();
							for (Object attributeName : ((Map) attributes).keySet())
							{
								attributesMap.put((String) attributeName, (String) vom
										.toSingleString(((Map) attributes).get(attributeName)));
							}
							change.setAttributes(attributesMap);
						}

						changes.add(change);
					}
				}
			}
		}
		catch (LDAPException e)
		{
			throw new InternalErrorException("Error getting accounts list", e);
		}
		catch (InternalErrorException e)
		{
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException(e.getMessage(), e);
		} finally {
			Watchdog.instance().dontDisturb();
		}
		return changes;
	}

	public boolean hasMoreData () throws InternalErrorException
	{
		return !firstChange;
	}

	public String getNextChange () throws InternalErrorException
	{
		if (lastUploadedChange == null)
			return null;
		else
			return Long.toString(lastUploadedChange.longValue() + 1);
	}

	public void debugModifications (String action, String dn,
			LDAPModification mods[])
	{
		if (debugEnabled)
		{
			log.info("=========================================================");
			log.info(action + " object " + dn);
			for (int i = 0; i < mods.length; i++)
			{
				LDAPModification mod = mods[i];
				debugAttribute(mod.getOp(), mod.getAttribute());
			}
			log.info("=========================================================");
		}
	}

	public void debugModifications (String action, String dn,
			LDAPAttributeSet atts)
	{
		if (debugEnabled)
		{
			log.info("=========================================================");
			log.info(action + " object " + dn);
			for (Iterator iterator = atts.iterator(); iterator.hasNext();)
			{
				LDAPAttribute att = (LDAPAttribute) iterator.next();
				debugAttribute(LDAPModification.ADD, att);
			}
			log.info("=========================================================");
		}
	}

	private void debugAttribute (int op, LDAPAttribute ldapAttribute)
	{
		String attAction =
				op == LDAPModification.ADD ? "ADD"
						: op == LDAPModification.DELETE ? "DELETE" : "REPLACE";
		StringBuffer b = new StringBuffer(attAction);
		b.append(" ").append(ldapAttribute.getName());
		if (op != LDAPModification.DELETE)
		{
			b.append(" = [");
			String[] v = ldapAttribute.getStringValueArray();
			for (int j = 0; j < v.length; j++)
			{
				if (j > 0)
					b.append(", ");
				b.append(v[j]);
			}
			b.append("]");
		}
		log.info(b.toString());
	}

	public Account getAccountInfo (String userAccount) throws RemoteException,
			InternalErrorException
	{
		ExtensibleObject eo;
		Watchdog.instance().interruptMe(getDispatcher().getTimeout());
		try
		{
			eo = findExtensibleUser(userAccount);
		}
		catch (LDAPException e)
		{
			throw new InternalErrorException(e.getMessage());
		}
		catch (InternalErrorException e)
		{
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException(e.getMessage(), e);
		} finally {
			Watchdog.instance().dontDisturb();
		}

		if (eo == null)
			return null;
		ExtensibleObjects parsed = objectTranslator.parseInputObjects(eo);
		for (ExtensibleObject peo : parsed.getObjects())
		{
			Account account = vom.parseAccount(peo);
			if (account != null)
				return account;
		}
		return null;
	}

	public List<RolGrant> getAccountGrants (String userAccount)
			throws RemoteException, InternalErrorException
	{
		Rol userRole; // User role
		LinkedList<RolGrant> rolesList = new LinkedList<RolGrant>(); // User roles
		LDAPEntry userEntry;	 // User LDAP entry
		Watchdog.instance().interruptMe(getDispatcher().getTimeout());
		try
		{
			ExtensibleObject eo = findExtensibleUser(userAccount);
			LDAPAttribute memberofattr; // User LDAP groups
			String userGroups[]; // User group array

			Object memberofattr1 = eo.getAttribute("dn");
			userEntry = searchEntry(memberofattr1.toString());
			memberofattr = userEntry.getAttribute("memberOf");
			userGroups =
					(memberofattr == null ? new String[] {} : memberofattr
							.getStringValueArray());

			// Process the user groups
			for (int i = 0; i < userGroups.length; i++)
			{
				String group =
						searchEntry(userGroups[i]).getAttribute(SAM_ACCOUNT_NAME_ATTRIBUTE)
								.getStringValue();

				userRole = getRoleFullInfo(group);

				if (userRole != null)
				{
					log.info("User {} belongs to [{}]", userAccount, userRole.getNom());
					RolGrant rg = new RolGrant();
					rg.setOwnerAccountName(userAccount);
					rg.setRolName(userRole.getNom());
					rg.setDispatcher(getCodi());
					rg.setEnabled(true);
					rg.setOwnerDispatcher(getCodi());
					rolesList.add(rg);
				}
			}
		}
		catch (LDAPException e)
		{
			throw new InternalErrorException(e.getMessage());
		}
		catch (InternalErrorException e)
		{
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
			case ',':
				sb.append("\\,");
				break;
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
}
