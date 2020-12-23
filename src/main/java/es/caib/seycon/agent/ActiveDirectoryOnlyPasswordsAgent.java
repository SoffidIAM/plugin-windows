package es.caib.seycon.agent;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.rmi.RemoteException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Vector;

import javax.management.relation.Role;
import javax.naming.directory.SearchResult;

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
import com.novell.ldap.controls.LDAPPagedResultsControl;
import com.novell.ldap.controls.LDAPPagedResultsResponse;

import es.caib.seycon.ng.comu.Grup;
import es.caib.seycon.ng.comu.LlistaCorreu;
import es.caib.seycon.ng.comu.Maquina;
import es.caib.seycon.ng.comu.Password;
import es.caib.seycon.ng.comu.Rol;
import es.caib.seycon.ng.comu.RolGrant;
import es.caib.seycon.ng.comu.Usuari;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownUserException;
import es.caib.seycon.ng.sync.intf.GroupMgr;
import es.caib.seycon.ng.sync.intf.HostMgr;
import es.caib.seycon.ng.sync.intf.KerberosAgent;
import es.caib.seycon.ng.sync.intf.KerberosPrincipalInfo;
import es.caib.seycon.ng.sync.intf.MailAliasMgr;
import es.caib.seycon.ng.sync.intf.ReconcileMgr;
import es.caib.seycon.ng.sync.intf.RoleMgr;
import es.caib.seycon.ng.sync.intf.UserMgr;
import es.caib.seycon.util.TimedOutException;
import es.caib.seycon.util.TimedProcess;

/**
 * Agente que gestiona los usuarios y contraseñas del Active Directory Hace uso
 * de las librerias jldap de Novell
 * 
 * Afegim la cerca de màquines marcades com a controlador de domini (DC), perquè
 * en aquest cas s'ignore la tasca UpdateHost (si ja existeix com a DC)
 * 
 * @author $Author: u07286 $
 * @version $Revision: 1.8 $
 */

public class ActiveDirectoryOnlyPasswordsAgent extends WindowsNTBDCAgent implements UserMgr,
		KerberosAgent, ReconcileMgr
{

	final static int ADS_UF_ACCOUNTDISABLE = 0x2;

	final static int ADS_UF_LOCKOUT = 0x10;

	final static int ADS_UF_NORMAL_ACCOUNT = 0x200;

	final static int ADS_UF_DONT_EXPIRE_PASSWD = 0x10000;

	final static int ADS_UF_TRUSTED_FOR_DELEGATION = 0x80000;

	final static int ADS_UF_PASSWORD_EXPIRED = 0x800000;

	private static final long serialVersionUID = 1L;

	/** Puerto de conexion LDAP * */
	static final int ldapPort = LDAPConnection.DEFAULT_SSL_PORT;

	/** Version del servidor LDAP */
	static final int ldapVersion = LDAPConnection.LDAP_V3;

	private static final long DOMAIN_GUEST_RID = 514;

	/** Usuario root de conexión LDAP */
	String loginDN;

	/** Password del usuario administrador cn=root,dc=caib,dc=es */
	Password password;

	/** HOST donde se aloja LDAP */
	String ldapHost;

	/** Rama base del arbol */
	String baseDN;

	/** ofuscador de claves SHA */
	static MessageDigest digest;

	// Vamos a er la hora en la que empieza y la hora en la que acaba.
	long inicio;

	long fin;

	int usuarios = 0;

	// --------------------------------------------------------------
	static Hashtable pool = new Hashtable();

	/**
	 * Constructor
	 * 
	 * @param params
	 *          Parámetros de configuración: <li>0 = host</li> <li>1 = Rama base
	 *          del arbol</li> <li>2 = código de usuario LDAP</li> <li>3 =
	 *          contraseña de acceso LDAP</li>
	 */
	public ActiveDirectoryOnlyPasswordsAgent () throws RemoteException
	{
		super();
	}

	@Override
	public void init ()
	{
		loginDN = getDispatcher().getParam2();
		password = Password.decode(getDispatcher().getParam3());
		ldapHost = getDispatcher().getParam0();
		baseDN = getDispatcher().getParam1();
		clustered = ("cluster".equalsIgnoreCase(getDispatcher().getParam4()));
		setquota = ("quota".equalsIgnoreCase(getDispatcher().getParam5()));
		allowedDrives = getDispatcher().getParam6();

		log.debug("Iniciado ActiveDirectoryAgent improved user=" + loginDN, null, null);
		try
		{
			javaDisk = new bubu.util.javadisk();
		}
		catch (Throwable e)
		{
			e.printStackTrace();
		}
	}
	
	@Override
	public boolean validateUserPassword (String user, Password password)
			throws RemoteException, InternalErrorException
	{
		LDAPConnection conn = null;
		try
		{

			LDAPEntry entry;
			entry = findSamAccount(user);
			conn = new LDAPConnection(new LDAPJSSESecureSocketFactory());
			conn.connect(ldapHost, ldapPort);
			conn.bind(ldapVersion, entry.getDN(), password
					.getPassword().getBytes("UTF8"));
			conn.disconnect();
			return true;
		}
		catch (UnsupportedEncodingException e)
		{
			return false;
		}
		catch (LDAPException e)
		{
			log.info("Error connecting as user " + user + ":" + e.toString());
			return false;
		}
		finally {}
	}

	private LDAPEntry findSamAccount (String user) throws LDAPException,
			InternalErrorException
	{
		LDAPEntry entry;
		String searchFilter = "(&(objectClass=user)(sAMAccountName=" + escapeLDAPSearchFilter(user) + "))";
		LDAPSearchResults search = getConnection().search(baseDN, LDAPConnection.SCOPE_SUB, searchFilter, null, false);
		if (search.hasMore())
		{
			try{
				entry = search.next();
			}catch(LDAPReferralException ldapError){
				System.out.println("User " + user + "is not an AD user.");
				entry = null;
			}
		} else {
			entry = null;
		}
		return entry;
	}
	
	/**
	 * 
	 */
	public void removeUser (String user) throws RemoteException,
			InternalErrorException
	{
	}

	/**
	 * Actualiza los datos del usuario de la clase inetOrgPersonCaib Inserta si es
	 * necesario una entrada de la clase inetOrgCaibPerson en el directorio LDAP.<BR>
	 * Si el usuario no está activo elimina la entrada del directorio LDAP
	 * 
	 * @throws InternalErrorException
	 *           Error en la propagación de datos al directorio LDAP.
	 */
	public void updateUser (String user, Usuari ui) throws RemoteException,
			InternalErrorException
	{
	}

	private void localUpdateUserPassword (String user, Usuari ui,
			Password password, boolean mustchange, boolean hasPassword)
			throws RemoteException, InternalErrorException, LDAPException,
			UnknownUserException
	{
		LDAPAttribute atributo;
		LDAPEntry usuario = findSamAccount(user);
		LDAPConnection lc = getConnection();
		synchronized (lc)
		{
			ArrayList modList = new ArrayList();
			if (usuario != null)
			{
				// Asignar la contraseña
				byte v[];
				try
				{
					v = ("\"" + password.getPassword() + "\"").getBytes("UTF-16LE");
				}
				catch (UnsupportedEncodingException e)
				{
					throw new InternalErrorException("Error generating password: "
							+ e.toString(), e);
				}

				atributo = new LDAPAttribute("unicodePwd", v);
				if (hasPassword)
				{
					modList.add(new LDAPModification(LDAPModification.REPLACE, atributo));
				}
				else
				{
					modList.add(new LDAPModification(LDAPModification.ADD, atributo));
				}
				// Desbloquear el usuario
				int status = 0;
				LDAPAttribute att = usuario.getAttribute("userAccountControl");
				if (att != null)
					status = Integer.decode(att.getStringValue()).intValue();
				// Quitar el bloqueo
				status = status & (~ADS_UF_LOCKOUT);
				// Poner el flag de cambiar en el próximo reinicio
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
				// Poner estado de cuenta normal
				status = status | ADS_UF_NORMAL_ACCOUNT;
				addModification(modList, usuario, new LDAPAttribute(
						"userAccountControl", Integer.toString(status)));
				// Commit de los cambios
				LDAPModification[] mods = new LDAPModification[modList.size()];
				mods = (LDAPModification[]) modList.toArray(new LDAPModification[0]);
				lc.modify(usuario.getDN(), mods);
			}
		}
	}

	/**
	 * Actualiza la contraseña del usuario. Genera la ofuscación SHA-1 y la asigna
	 * al atributo userpassword de la clase inetOrgPersonCAIB
	 */
	public void updateUserPassword (String user, Usuari ui, Password password,
			boolean mustchange) throws RemoteException, InternalErrorException
	{
		try
		{
			localUpdateUserPassword(user, ui, password, mustchange, false);
		}
		catch (LDAPException e)
		{
			if (LDAPException.ATTRIBUTE_OR_VALUE_EXISTS == e.getResultCode())
			{
				try
				{
					localUpdateUserPassword(user, ui, password, mustchange, true);
				}
				catch (Exception exception)
				{
					if (exception instanceof LDAPException)
					{
						cerrarConexion();
					}
					log.warn("Error changing password: UpdateUserPassword (" + user
							+ ")", exception);
					throw new InternalErrorException("Error changing password:"
							+ exception.getMessage(), exception);
				}
			}
			else
			{
				log.warn("Error changing passwrod: UpdateUserPassword (" + user + ")", e);
				throw new InternalErrorException("Error changing password:"
						+ e.getMessage(), e);
			}
		}
		catch (UnknownUserException e) {}
	}

	/**
	 * Obtiene conexión con el directorio LDAP
	 * 
	 * @throws InternalErrorException
	 *           imposible conectar con el servidor LDAP
	 */
	private LDAPConnection getConnection () throws InternalErrorException
	{
		LDAPConnection conn = (LDAPConnection) pool.get(getDispatcher().getCodi());
		if (conn == null || !conn.isConnected() || !conn.isBound()
				|| !conn.isConnectionAlive())
		{
			try
			{
				conn = new LDAPConnection(new LDAPJSSESecureSocketFactory());
				conn.connect(ldapHost, ldapPort);
				conn.bind(ldapVersion, loginDN + ", " + baseDN, password.getPassword()
						.getBytes("UTF8"));
				pool.put(getDispatcher().getCodi(), conn);
			}
			catch (UnsupportedEncodingException e)
			{
				throw new InternalErrorException("Error encoding UTF8:"
						+ e.toString(), e);
			}
			catch (LDAPException e)
			{
				throw new InternalErrorException("Failed to connect to LDAP: ("
						+ loginDN + "/" + password + ")" + e.toString(), e);
			}
		}
		return (conn);
	}

	/**
	 * Cierra la conexión con el directorio LDAP.
	 * 
	 * @throws InternalErrorException
	 *           imposible conectar con el servidor LDAP
	 */
	private void cerrarConexion ()
	{
		LDAPConnection conn = (LDAPConnection) pool.get(getDispatcher().getCodi());
		if (conn != null)
		{
			synchronized (conn)
			{
				pool.remove(getDispatcher().getCodi());
				try
				{
					conn.disconnect();
				}
				catch (LDAPException e) {}
			}
		}
	}

	/**
	 * Actualiza los groupOfNames en el directorio LDAP Si el groupOfNames se
	 * queda sin members se elimina del directorio Inserta si es necesario una
	 * entrada de la clase groupOfNames en el directorio LDAP.<BR>
	 * 
	 * @params role groupOfNames a modificar
	 * @params bd No se utiliza se pasa siempre a null
	 * @throws InternalErrorException
	 *           Error en la propagación de datos al directorio LDAP.
	 */
	public void updateRole (Rol rol) throws RemoteException,
			InternalErrorException
	{
	}

	public void removeRole (String rolName, String dispatcher)
	{
		// No borrar
	}


	/**
	 * Elimina un groupOfNames en el directorio LDAP
	 * 
	 * @param Entry
	 *          Entrada en el directorio LDAP del groupOfNames a eliminar
	 * @param users
	 *          Listado de members pertenecientes al groupOfNames rol
	 */
	public void deleteGroup (String group) throws InternalErrorException
	{
	}


	public void removeGroup (String key) throws RemoteException,
			InternalErrorException
	{
	}

	public void updateGroup (String group, Grup gi) throws InternalErrorException
	{
	}

	public void updateHost (Maquina maquina) throws RemoteException,
			InternalErrorException
	{
	}

	public void removeHost (String name) throws RemoteException,
			InternalErrorException {}

	/**
	 * @param value
	 * @param attribute
	 * @param entry
	 * @return
	 */
	private LDAPModification createModification (LDAPEntry entry,
			LDAPAttribute attribute)
	{
		if (entry.getAttribute(attribute.getName()) == null
				&& !attribute.getName().equals("unicodePwd"))
			return new LDAPModification(LDAPModification.ADD, attribute);
		else
			return new LDAPModification(LDAPModification.REPLACE, attribute);
	}
	
	/**
	 * @param modList
	 */
	private LDAPModification addModification (ArrayList modList, LDAPEntry entry,
			LDAPAttribute attribute)
	{
		LDAPModification m = createModification(entry, attribute);
		modList.add(m);
		return m;
	}


	public KerberosPrincipalInfo createServerPrincipal (String server)
			throws InternalErrorException
	{
		try
		{

			String uid = "SEYCON_" + server;
			if (uid.indexOf('.') > 0)
				uid = uid.substring(0, uid.indexOf('.'));
			if (uid.length() > 20)
				uid = uid.substring(0, 20);

			String realm = getRealmName();
			String principal = "SEYCON/" + server;
			KerberosPrincipalInfo result = new KerberosPrincipalInfo();
			result.setUserName(uid);
			result.setPrincipalName(principal + "@" + realm);
			result.setPassword(getServer().generateFakePassword(
					getDispatcher().getDominiContrasenyes()));
			byte v[];
			try
			{
				v = ("\"" + result.getPassword().getPassword() + "\"")
						.getBytes("UTF-16LE");
			}
			catch (UnsupportedEncodingException e)
			{
				throw new InternalErrorException("Error generating password: "
						+ e.toString(), e);
			}
			LDAPEntry entry = findSamAccount(uid);
			LDAPConnection lc = getConnection();
			synchronized (lc)
			{
				if (entry == null)
				{// Es nuevo
					String dn = "cn=" + uid + ", cn=Users, " + baseDN;
					LDAPAttributeSet attributeSet = new LDAPAttributeSet();
					attributeSet.add(new LDAPAttribute("objectclass",
							new String[] { "user" }));
					attributeSet.add(new LDAPAttribute("cn", new String[] { uid }));
					attributeSet.add(new LDAPAttribute("sAMAccountName", uid));
					attributeSet.add(new LDAPAttribute("givenName",
							"Service account for " + principal));
					attributeSet.add(new LDAPAttribute("displayName",
							"Service account for " + principal));
					attributeSet.add(new LDAPAttribute("userAccountControl", Integer
							.toString(ADS_UF_ACCOUNTDISABLE | ADS_UF_NORMAL_ACCOUNT
									| ADS_UF_TRUSTED_FOR_DELEGATION)));
					// Asociar la ejecución como servicio
					attributeSet
							.add(new LDAPAttribute("servicePrincipalName", principal));
					log.warn("Creating {}", dn, null);
					entry = new LDAPEntry(dn, attributeSet);
					lc.add(entry);
				}
				// Asignar la contraseña
				ArrayList<LDAPModification> modList = new ArrayList<LDAPModification>();

				LDAPAttribute atributo = new LDAPAttribute("unicodePwd", v);
				modList.add(new LDAPModification(LDAPModification.REPLACE, atributo));
				int status = ADS_UF_NORMAL_ACCOUNT | ADS_UF_DONT_EXPIRE_PASSWD |
						ADS_UF_TRUSTED_FOR_DELEGATION;
				addModification(modList, entry, new LDAPAttribute("userAccountControl",
						Integer.toString(status)));
				// Commit de los cambios
				LDAPModification[] mods = new LDAPModification[modList.size()];
				mods = (LDAPModification[]) modList.toArray(new LDAPModification[0]);
				lc.modify(entry.getDN(), mods);
				if (true)
					return result;

				File f = File.createTempFile(realm, "ktab");
				log.info("Generating ktab file = {}", f, null);
				TimedProcess p = new TimedProcess(20000);
				p.exec("ktpass.exe " + "-princ \"" + principal + "\" " + "-out \""
						+ f.getPath() + "\" " + "-pass \"" + password.getPassword() + "\" "
						+ "-mapuser \"" + uid + "@" + realm + "\" "
						+ "-ptype KRB5_NT_PRINCIPAL "
				// "-crypto DES-CBC-MD5"
				);
				log.info("ktpass result={}/{}", p.getOutput(), p.getError());
				byte ktab[] = null;
				byte buffer[] = new byte[4096];
				FileInputStream in = new FileInputStream(f);
				int read = in.read(buffer);
				while (read > 0)
				{
					if (ktab == null)
					{
						ktab = new byte[read];
						System.arraycopy(buffer, 0, ktab, 0, read);
					}
					else
					{
						byte[] oldktab = ktab;
						ktab = new byte[read + oldktab.length];
						System.arraycopy(oldktab, 0, ktab, 0, oldktab.length);
						System.arraycopy(buffer, 0, ktab, oldktab.length, read);
					}
					read = in.read(buffer);
				}
				in.close();
				result.setKeytab(ktab);
				return result;
			}
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

	/**
	 * Actualiza los datos del usuario de la clase inetOrgPersonCaib Inserta si es
	 * necesario una entrada de la clase inetOrgCaibPerson en el directorio LDAP.<BR>
	 * Si el usuario no está activo elimina la entrada del directorio LDAP
	 * 
	 * @throws InternalErrorException
	 *           Error en la propagación de datos al directorio LDAP.
	 */
	public void updateUser (String user, String description)
			throws RemoteException, InternalErrorException
	{
	}


	/*
	 * (non-Javadoc)
	 * @see es.caib.seycon.ng.sync.intf.ReconcileMgr#getAccountsList()
	 */
	public List<String> getAccountsList () throws RemoteException,
			InternalErrorException
	{
		LinkedList<String> userAccounts = new LinkedList<String>(); // User accounts

		try
		{
			LDAPConnection lc = getConnection();
			LDAPSearchConstraints oldConst = lc.getSearchConstraints();	// Save search constraints
			
			synchronized (lc)
			{
				LDAPEntry entry = null;
				String searchBase = "CN=Users, " + baseDN;
				String searchFilter = "(&(objectClass=user)(cn=*))";
				int searchScope = LDAPConnection.SCOPE_ONE;
				LDAPPagedResultsControl pageResult =
						new LDAPPagedResultsControl(lc.getSearchConstraints()
							.getMaxResults(), false);

				do
				{
					LDAPSearchConstraints constraints = lc.getSearchConstraints();
					constraints.setControls(pageResult);
					lc.setConstraints(constraints);

					LDAPSearchResults searchResults = lc.search(searchBase, searchScope,
							searchFilter, null,	// return all attributes
							false);	// return attrs and values

					// Process results
					while (searchResults.hasMore())
					{
						entry = searchResults.next();

						userAccounts.add(entry.getAttribute("CN").getStringValue());
					}

					LDAPControl responseControls[] = searchResults.getResponseControls();
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
			}
			
			lc.setConstraints(oldConst);
		}

		catch (LDAPException e)
		{
			cerrarConexion();

			String msg = "Error to find users: ";
			log.warn(msg, e);
			throw new InternalErrorException(msg + e.toString(), e);
		}
		
		catch (Exception e)
		{
			log.error(e.getMessage());
		}

		return userAccounts;
	}

	/*
	 * (non-Javadoc)
	 * @see es.caib.seycon.ng.sync.intf.ReconcileMgr#getUserInfo(java.lang.String)
	 */
	public Usuari getUserInfo (String userAccount) throws RemoteException,
			InternalErrorException
	{
		Usuari userInfo = new Usuari(); // User data

		try
		{
			LDAPEntry entry = findSamAccount(userAccount);

			userInfo.setCodi(entry.getAttribute("CN").getStringValue());
			userInfo.setNom(getUserFullName(entry));
		}

		catch (Exception e)
		{
			cerrarConexion();

			String msg =
					String.format("Error to find user '%s' data:", userAccount);
			log.warn(msg, e);
			throw new InternalErrorException(msg + e.toString(), e);
		}

		return userInfo;
	}

	/**
	 * Get the user full name.
	 * 
	 * @param entry
	 *          LDAP entry to obtain the user full name.
	 * @return String that contains the user full name.
	 */
	private String getUserFullName (LDAPEntry entry)
	{
		String userName; // User name
		String userSurname; // User surname
		String fullName; // User full name

		// Check user name
		if ((entry.getAttribute("givenName") != null)
				&& (entry.getAttribute("sn") != null))
		{
			userName = entry.getAttribute("givenName").getStringValue();
			userSurname = entry.getAttribute("sn").getStringValue();

			fullName = String.format("%s %s", userName, userSurname);
		}

		else
		{
			fullName = entry.getAttribute("CN").getStringValue();
		}

		return fullName;
	}

	/*
	 * (non-Javadoc)
	 * @see es.caib.seycon.ng.sync.intf.ReconcileMgr#getRolesList()
	 */
	public List<String> getRolesList () throws RemoteException,
			InternalErrorException
	{
		return null;
	}

	/*
	 * (non-Javadoc)
	 * @see
	 * es.caib.seycon.ng.sync.intf.ReconcileMgr#getRoleFullInfo(java.lang.String )
	 */
	public Rol getRoleFullInfo (String roleName) throws RemoteException,
			InternalErrorException
	{
		return null;
	}

	/*
	 * (non-Javadoc)
	 * @see es.caib.seycon.ng.sync.intf.ReconcileMgr#getAccountsRoleGranted()
	 */
	public List<RolGrant> getAccountsRoleGranted () throws RemoteException,
			InternalErrorException
	{
		// TODO Auto-generated method stub
		return null;
	}

	/*
	 * (non-Javadoc)
	 * @see
	 * es.caib.seycon.ng.sync.intf.ReconcileMgr#getAccountRoles(java.lang.String )
	 */
	public List<Rol> getAccountRoles (String userAccount) throws RemoteException,
			InternalErrorException
	{
		return null;
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

	public String parseKerberosToken(String serverPrincipal, byte[] keytab, byte[] token)
			throws InternalErrorException {
		return null;
	}

}
