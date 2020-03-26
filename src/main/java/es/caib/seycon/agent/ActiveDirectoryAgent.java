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
import com.novell.ldap.LDAPAuthHandler;
import com.novell.ldap.LDAPAuthProvider;
import com.novell.ldap.LDAPBindHandler;
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
import com.soffid.iam.api.AccountStatus;

import es.caib.seycon.ng.comu.Account;
import es.caib.seycon.ng.comu.Grup;
import es.caib.seycon.ng.comu.LlistaCorreu;
import es.caib.seycon.ng.comu.Maquina;
import es.caib.seycon.ng.comu.Password;
import es.caib.seycon.ng.comu.Rol;
import es.caib.seycon.ng.comu.RolGrant;
import es.caib.seycon.ng.comu.Usuari;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownGroupException;
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

public class ActiveDirectoryAgent extends WindowsNTBDCAgent implements UserMgr,
		RoleMgr, GroupMgr, MailAliasMgr, HostMgr, KerberosAgent, ReconcileMgr
{

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
	public ActiveDirectoryAgent () throws RemoteException
	{
		super();
	}

	@Override
	public void init ()
	{
		loginDN = getDispatcher().getParam2();
		password = Password.decode(getDispatcher().getParam3());
		// password = params[1];
		ldapHost = getDispatcher().getParam0();
		baseDN = getDispatcher().getParam1();
		clustered = ("cluster".equalsIgnoreCase(getDispatcher().getParam4()));
		setquota = ("quota".equalsIgnoreCase(getDispatcher().getParam5()));
		allowedDrives = getDispatcher().getParam6();

		log.debug("Iniciado ActiveDirectoryAgent improved user=" + loginDN
				+ " pass=" + password + "(" + password.getPassword() + ")", null, null);
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
			conn = new LDAPConnection(new LDAPJSSESecureSocketFactory());
			conn.connect(ldapHost, ldapPort);
			conn.bind(ldapVersion, "cn=" + user + ",cn=Users," + baseDN, password
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
	
	/**
	 * 
	 */
	public void removeUser (String user) throws RemoteException,
			InternalErrorException
	{
		LDAPEntry usuario;
		log.info("Search user {} ", user, null);
		usuario = searchUser(user);
		if (usuario != null)
		{
			Account acc = getServer().getAccountInfo(user, getDispatcher().getCodi());
			if ( acc != null && acc.getStatus() == AccountStatus.REMOVED)
			{
				try
				{
					LDAPConnection lc = getConnection();
					synchronized (lc)
					{
						String deleteDN = usuario.getDN();
						lc.delete(deleteDN);
					}
				}
				catch (LDAPException e)
				{
					cerrarConexion();
					throw new InternalErrorException("Error deleting user " + user + ":"
							+ e.toString(), e);
				}
			}
			else
			{
				log.info("Disable user {} ", user, null);
				disableUser(usuario);
			}
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
	public void updateUser (String user, Usuari ui) throws RemoteException,
			InternalErrorException
	{
		LDAPEntry usuario;
		log.info("Search user {} ", user, null);
		usuario = searchUser(user);
		if (usuario == null && ui != null)
		{
			log.info("Adding user {} ", user, null);
			addUser(user, ui);
			usuario = searchUser(user);
		}
		if (usuario != null)
		{
			log.info("Update user data {} ", user, null);
			try
			{
				int status = 0;
				LDAPAttribute att = usuario.getAttribute("userAccountControl");

				if (att != null)
				{
					status = Integer.decode(att.getStringValue()).intValue();
					// Si el usuario estaba desactivado y se vuelve
					// a activar se le asigna una contraseña aleatoria
					// para evitar error en Windows
					if (status != 0
							&& (status & ADS_UF_ACCOUNTDISABLE) == ADS_UF_ACCOUNTDISABLE)
					{
						try
						{
							// Asignamos una contraseña aleatoria y hacemos
							// que la cambie cuando se conecte el usuario
							Password pass =
									getServer().getOrGenerateUserPassword(user, getCodi());
							updateUserPassword(user, ui, pass, true);
							// Activamos el usuario (como cuando se crea de
							// nuevo)
							LDAPAttribute att_reactiva =
									new LDAPAttribute("userAccountControl",
											Integer.toString(ADS_UF_ACCOUNTDISABLE
													+ ADS_UF_NORMAL_ACCOUNT));
							LDAPModification mod_reactiva =
									createModification(usuario, att_reactiva);
							LDAPConnection lc = getConnection();
							synchronized (lc)
							{
								lc.modify(usuario.getDN(), mod_reactiva);
							}
						}
						catch (RemoteException e)
						{
							cerrarConexion();
						}
					}
				}
			}
			catch (Exception ex)
			{
				;// No hacemos nada
			}
			// Modifica los datos de la entrada de un usuario del directorio
			// LDAP:
			updateUserData(usuario, user, ui);
			updateUserGroups(user, ui, usuario);
		}
		log.info("Updated user {} ", user, null);
	}

	private void updateUserGroups (String user, Usuari ui, LDAPEntry usuario)
			throws RemoteException, InternalErrorException
	{
		// Aquí llegamos en usuarios nuevos y existentes ACTIVOS
		// Gestionamos la membresía del usuario a roles y grupos
		// en el atributo member-of del usuario lo tenemos
		LDAPAttribute memberofattr = usuario.getAttribute("memberOf");
		String grupsCAIBUsuari[] =
				memberofattr == null ? new String[] {} : memberofattr
						.getStringValueArray();
		HashSet<String> h_grupsCAIBUsuari = new HashSet(); // caib
		for (int i = 0; i < grupsCAIBUsuari.length; i++)
		{
			log.info("User {} belongs to [{}]", user, extractCN(grupsCAIBUsuari[i]));
			h_grupsCAIBUsuari.add(extractCN(grupsCAIBUsuari[i]).toLowerCase());
		}
		// roles seycon: rolesUsuario - grupos seycon: grupsUsuari
		// Obtenim tots els grups/rols de l'usuari
		// Obtenim els rols/grups de l'usuari des del seycon
		try
		{
			HashSet<String> groups = new HashSet<String>();
			for (RolGrant grant : getServer().getAccountRoles(user, getCodi()))
			{
				if (!groups.contains(grant.getRolName()))
					groups.add(grant.getRolName());
			}
			for (Grup grup : getServer().getUserGroups(user, getCodi()))
			{
				if (!groups.contains(grup.getCodi()))
					groups.add(grup.getCodi());
			}

			for (Iterator<String> it = groups.iterator(); it.hasNext();)
			{
				String group = it.next();
				log.info("User {} should belong to [{}]", user, group);
				if (!h_grupsCAIBUsuari.remove(group.toLowerCase()))
				{
					addGroupMember(group, user, usuario);
				}
			}
			// Esborram dels grups excedents
			for (Iterator it = h_grupsCAIBUsuari.iterator(); it.hasNext();)
			{
				String grup = (String) it.next();
				removeGroupMember(grup, user, usuario);
			}
		}
		catch (LDAPException e)
		{
			throw new InternalErrorException("Error updating groups", e);
		}
		catch (UnknownUserException e)
		{
			throw new InternalErrorException("Error updating groups", e);
		}
	}

	private void removeGroupMember (String group, String user,
			LDAPEntry userEntry) throws InternalErrorException, LDAPException
	{
		log.info("Removing user {} from group {}", user, group);
		LDAPConnection c = getConnection();
		synchronized (c)
		{
			LDAPEntry entry = getGroupEntry(group);
			if (entry == null)
			{
				return;
			}
			else
			{
				c.modify(entry.getDN(), new LDAPModification(LDAPModification.DELETE,
						new LDAPAttribute("member", userEntry.getDN())));
			}
		}
	}

	private void addGroupMember (String group, String user, LDAPEntry userEntry)
			throws InternalErrorException, LDAPException
	{
		log.info("Adding user {} to group {}", user, group);
		LDAPConnection c = getConnection();
		synchronized (c)
		{
			LDAPEntry entry = getGroupEntry(group);
			if (entry == null)
			{
				entry = createGroupEntry(group);
			}
			c.modify(entry.getDN(), new LDAPModification(LDAPModification.ADD,
					new LDAPAttribute("member", userEntry.getDN())));
			log.info("Added", null, null);
		}
	}

	private String extractCN (String x500Name) throws InternalErrorException
	{
		try
		{
			LDAPConnection c = getConnection();
			LDAPEntry e = c.read(x500Name,  
							new String[] {"sAMAccountName"}); 
			if (e != null)
			{
				LDAPAttribute att = e.getAttribute("sAMAccountName");

				if (att != null)
				{
					return att.getStringValue();
				}
			}
		}
		catch (LDAPException e)
		{
			if (e.getResultCode() == LDAPException.NO_SUCH_OBJECT)
			{
				int i = x500Name.toLowerCase().indexOf("cn=");
				if (i < 0)
					return null;
				int j = x500Name.indexOf(",", i);
				if (j < 0)
					return x500Name.substring(i + 3);
				else
					return x500Name.substring(i + 3, j);
			}
			else
				throw new InternalErrorException ("Error getting entry "+x500Name);
		}

		return null;
	}

	private void localUpdateUserPassword (String user, Usuari ui,
			Password password, boolean mustchange, boolean hasPassword)
			throws RemoteException, InternalErrorException, LDAPException,
			UnknownUserException
	{
		LDAPAttribute atributo;
		LDAPEntry usuario = null;
		if (user.toLowerCase().equals("administrator"))
			return;
		if (user.toLowerCase().equals("administrador"))
			return;
		LDAPConnection lc = getConnection();
		synchronized (lc)
		{
			usuario = searchUser(user);
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
				// Poner el flag de cambiar en el proximo rinicio
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
				cerrarConexion();
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
					throw new InternalErrorException("Error changing passwrod:"
							+ exception.getMessage(), exception);
				}
			}
			else
			{
				log.warn("Error changing passwrod: UpdateUserPassword (" + user + ")", e);
				throw new InternalErrorException("Error changing passwrod:"
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
				LDAPConstraints constraints = conn.getConstraints();
				constraints.setReferralFollowing(true);
				constraints.setReferralHandler(new LDAPAuthHandler()
				{
					public LDAPAuthProvider getAuthProvider (String host, int port)
					{
						try
						{
							return new LDAPAuthProvider(loginDN, password.getPassword().getBytes("UTF-8"));
						}
						catch (UnsupportedEncodingException e)
						{
							return new LDAPAuthProvider(loginDN, password.getPassword().getBytes());
						}
					}
				});
				conn.setConstraints(constraints);
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
	 * Method that implements the functionality to search user data on LDAP directory.
	 * 
	 * @param user
	 *          User code
	 * @return LDAPEntry LDAP directory entry
	 * @throws InternalErrorException
	 *           Error finding user
	 */
	private LDAPEntry searchUser (String user) throws InternalErrorException
	{
		try
		{
			LDAPConnection lc = getConnection();
			LDAPEntry entry = new LDAPEntry();

			synchronized (lc)
			{
				String searchFilter =
						"(&(objectclass=user)(sAMAccountName=" + escapeLDAPSearchFilter(user) + "))";
				int searchScope = LDAPConnection.SCOPE_SUB;
				LDAPSearchResults searchResults =
						lc.search(baseDN, searchScope, searchFilter, null, // return
																																// all
								// attributes
								false); // return attrs and values
				if (searchResults.hasMore())
				{
					entry = searchResults.next();
				}
				else
				{
					entry = null;
				}
				while (searchResults.hasMore())
					searchResults.next();
			}

			if (entry == null)
				log.info("Not found", null, null);
			else
				log.info("Found", null, null);

			return (entry);
		}
		catch (LDAPException e)
		{
			if (e.getResultCode() == LDAPException.NO_SUCH_OBJECT)
				return null;
			cerrarConexion();
			String msg = String.format("Error searching user '%s': ", user);
			log.warn(msg, e);
			throw new InternalErrorException(msg + e.toString(), e);
		}
	}

	/**
	 * Añade los datos de un usuario al directorio LDAP
	 * 
	 * @param ui
	 *          Informacion del usuario
	 * @throws InternalErrorException
	 *           Error al añadir el usuario al directorio LDAP
	 */
	private void addUser (String user, Usuari ui) throws InternalErrorException
	{
		try
		{
			String dn = getUserDN(user);

			// Alta de usuario
			LDAPConnection lc = getConnection();
			synchronized (lc)
			{
				LDAPAttributeSet attributeSet = new LDAPAttributeSet();
				attributeSet.add(new LDAPAttribute("objectclass",
						new String[] { "user" }));
				attributeSet.add(new LDAPAttribute("cn", new String[] { user }));
				attributeSet.add(new LDAPAttribute("sAMAccountName", user));
				attributeSet.add(new LDAPAttribute("userAccountControl", Integer
						.toString(ADS_UF_ACCOUNTDISABLE + ADS_UF_NORMAL_ACCOUNT)));
				// attributeSet.add(new LDAPAttribute("scriptPath",
				// "caiblogn.exe"));
				LDAPEntry newEntry = new LDAPEntry(dn, attributeSet);
				lc.add(newEntry);
				// Obtenim la seua password
				Password pass = getServer().getAccountPassword(user, getCodi());
				if (pass == null)
				{
					pass = getServer().generateFakePassword(user, getCodi());
					updateUserPassword(user, ui, pass, true);
				}
				else
				{
					// és la seua contrasenya, no l'ha de canviar
					updateUserPassword(user, ui, pass, false);
				}
			}
		}
		catch (LDAPException e)
		{
			cerrarConexion();
			String msg = "Error creating user " + user + ":";
			log.warn(msg, e);
			throw new InternalErrorException(msg + e.toString(), e);
		}
		catch (java.rmi.RemoteException e)
		{
			throw new InternalErrorException(e.toString(), e);
		}
	}

	/**
	 * @param ui
	 * @return
	 * @throws UnknownGroupException 
	 * @throws InternalErrorException 
	 */
	private String getUserDN (String user) throws InternalErrorException
	{
		try
		{
			Usuari ui = getServer().getUserInfo(user, getDispatcher().getCodi());
			String group = ui.getCodiGrupPrimari();
			String base = baseDN;
			boolean addUsers = true;
			while (group != null) {
				Grup groupInfo;
				try
				{
					groupInfo = getServer().getGroupInfo(group, getDispatcher().getCodi());
					if ((groupInfo.getTipus() != null) && groupInfo.getTipus().equals("uopn"))
					{
						base = "ou=" + groupInfo.getCodi() + "," + base;
						addUsers = false;
					}
					group = groupInfo.getCodiPare();
				}
				catch (UnknownGroupException e)
				{
					group = null;
				}
			} 
			if (addUsers)
				base = "cn=Users," + base;
			return "cn=" + user + "," + base;
		}
		catch (UnknownUserException e)
		{
			return "cn=" + user + ",cn=Users," + baseDN;
		}
	}

	/**
	 * @param ui
	 * @return
	 */
	private String getGroupDN (String group)
	{
		return "cn=" + group + ",cn=Users," + baseDN;
	}

	/**
	 * Busca los datos de un usuario en el directorio LDAP
	 * 
	 */
	private boolean hasAttribute (LDAPEntry entry, String attribute)
			throws InternalErrorException
	{
		try
		{
			boolean found = false;
			LDAPAttributeSet attributeSet = entry.getAttributeSet();
			for (Iterator iterator = attributeSet.iterator(); iterator.hasNext()
					&& !found;)
			{
				LDAPAttribute ldapAttribute = (LDAPAttribute) iterator.next();
				String attributeName = ldapAttribute.getName();
				found = found || attributeName.compareTo(attribute) == 0;
			}
			return found;
		}
		catch (Exception e)
		{
			cerrarConexion();
			throw new InternalErrorException("Failed to find user attribute: "
					+ e.toString(), e);
		}
	}

	/**
	 * Actualizamos el password del usuario Este método se utiliza cuando la
	 * contraseña actual del usuario es incorrecta y actualizar el atributo LDAP
	 * userAccountControl da un error 53 (UNWILLING_TO_PERFORM)
	 * 
	 * @param ui
	 * @param password
	 */
	private void updateIncorrectPassword (LDAPEntry usuario, String user,
			Usuari ui, Password password, boolean hasPassword, int status)
			throws LDAPException, InternalErrorException
	{
		LDAPConnection lc = getConnection();
		synchronized (lc)
		{
			LDAPAttribute atributo;

			ArrayList modList = new ArrayList();
			if (usuario != null && (ui == null || ui.getActiu().booleanValue()))
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
				// Aplicamos el status al usuario en el atributo
				// userAccountControl
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
	 * Modifica los datos de la entrada de un usuario del directorio LDAP
	 * 
	 * @param usuario
	 *          Entrada LDAP del usuario a modificar
	 * @param ui
	 *          Informacion del usuario a modificar en el seycon
	 * @throws InternalErrorException
	 *           Error al modificar el usuario al directorio LDAP
	 */
	private void updateUserData (LDAPEntry usuario, String user, Usuari ui)
			throws InternalErrorException
	{
		try
		{
			log.info("Updating user {} data", user, null);
			LDAPConnection lc = getConnection();
			synchronized (lc)
			{
				ArrayList modList = new ArrayList();
				ArrayList modListUserAccount = new ArrayList();

				addModification(modList, usuario,
						new LDAPAttribute("givenname", ui.getNom()));

				addModification(
						modList,
						usuario,
						new LDAPAttribute("sn", ui.getPrimerLlinatge()
								+ (ui.getSegonLlinatge() == null ? "" : " "
										+ ui.getSegonLlinatge())));

				addModification(modList, usuario,
						new LDAPAttribute("description", ui.getFullName()));

				// Servidor de perfiles
				if (ui.getServidorPerfil().equals("null"))
				{
					addDeletion(modList, usuario, "profilePath");
				}
				else
				{
					addModification(modList, usuario, new LDAPAttribute("profilePath",
							"\\\\" + ui.getServidorPerfil() + "\\PROFILES\\" + user));
				}

				// Homes
				if (ui.getServidorHome().equals("null"))
				{
					addDeletion(modList, usuario, "homeDrive");
					addDeletion(modList, usuario, "homeDirectory");
				}
				else
				{
					addModification(modList, usuario,
							new LDAPAttribute("homeDrive", "H:"));
					addModification(modList, usuario, new LDAPAttribute("homeDirectory",
							"\\\\" + ui.getServidorHome() + "\\" + user));
				}

				if (ui.getNomCurt() != null)
				{
					addModification(
							modList,
							usuario,
							new LDAPAttribute("mail", textify(ui.getNomCurt(),
									ui.getDominiCorreu())));
				}
				else
				{
					addDeletion(modList, usuario, "mail");
				}

				// Modificación del atributo userAccountControl:
				int status = 0;
				LDAPAttribute att = usuario.getAttribute("userAccountControl");

				if (att != null)
					status = Integer.decode(att.getStringValue()).intValue();

				// Quitar el disable
				status = status & (~ADS_UF_ACCOUNTDISABLE);
				// Quitar el lockout
				status = status & (~ADS_UF_LOCKOUT);
				// Quitar el flag de nunca caducar passwd
				status = status & (~ADS_UF_DONT_EXPIRE_PASSWD);
				// Poner estado de cuenta normal
				status = status | ADS_UF_NORMAL_ACCOUNT;

				// Añadimos esta modificación en una lista diferente
				addModification(modListUserAccount, usuario, new LDAPAttribute(
						"userAccountControl", Integer.toString(status)));

				// Intentamos hacer la modificación del userAccountControl
				// Esta puede fallar en el caso de que la contraseña actual
				// del usuario no sea correcta, por eso se hace por separado
				try
				{
					lc.modify(usuario.getDN(), (LDAPModification[]) modListUserAccount
							.toArray(new LDAPModification[0]));
				}
				catch (LDAPException lex)
				{
					// Analizamos la excepción, para ver si es por problemas de
					// contraseñas en tal caso el resultcode es
					// UNWILLING_TO_PERFORM

					if (lex.getResultCode() == LDAPException.UNWILLING_TO_PERFORM)
					{
						// Reseteamos la contraseña del usuario:
						// Asignamos una contraseña aleatoria y hacemos
						// que la cambie cuando se conecte el usuario
						// También se modifica el "userAccountControl"
						Password pass = getServer().generateFakePassword(user, getCodi());
						try
						{
							updateIncorrectPassword(usuario, user, ui, pass, false, status);
						}
						catch (LDAPException e)
						{
							if (LDAPException.ATTRIBUTE_OR_VALUE_EXISTS == e.getResultCode())
							{
								try
								{
									updateIncorrectPassword(usuario, user, ui, pass, true, status);
								}
								catch (LDAPException exception)
								{
									cerrarConexion();
									throw new InternalErrorException(
											"Error changing password:" + exception.getMessage(),
											exception);
								}
							}
							else
							{
								cerrarConexion();
								throw new InternalErrorException("Error changing password:"
										+ e.getMessage(), e);
							}
						}
					}
				}

				// Para ver qué modificación da error: TRAZAS u88683
				/*
				 * for (int i=0; i < modList.size(); i++) { try { LDAPModification mod =
				 * (LDAPModification) modList.get(i); lc.modify(entry.getDN(),mod); }
				 * catch (LDAPException exc) { String resultCode =
				 * exc.resultCodeToString(); throw new InternalErrorException
				 * ("<br><b>Error modificando entrada LDAP: "
				 * +" entrada: ("+(LDAPModification)
				 * modList.get(i)+")</b><br>Error causado = "+exc.toString()); } }
				 */

				// Esborrem attribut scriptPath, si existeix
				addDeletion(modList, usuario, "scriptPath");

				// Hacemos el resto de modificaciones
				lc.modify(usuario.getDN(),
						(LDAPModification[]) modList.toArray(new LDAPModification[0]));
			}
		}
		catch (LDAPException e)
		{
			throw new InternalErrorException("Entry: " + usuario.toString()
					+ " Error modifying user " + user + ": " + e.toString(), e);
		}
	}

	/**
	 * Deshabilita los datos de la entrada de un usuario del directorio LDAP
	 * 
	 * @param Entry
	 *          Entrada LDAP del usuario a modificar
	 * @throws InternalErrorException
	 *           Error al modificar el usuario al directorio LDAP
	 */
	private void disableUser (LDAPEntry entry) throws InternalErrorException
	{
		try
		{
			LDAPConnection lc = getConnection();
			synchronized (lc)
			{
				ArrayList modList = new ArrayList();

				addDeletion(modList, entry, "profilePath");
				addDeletion(modList, entry, "homeDrive");
				addDeletion(modList, entry, "homeDirectory");

				int status = 0;
				LDAPAttribute att = entry.getAttribute("userAccountControl");
				if (att != null)
					status = Integer.decode(att.getStringValue()).intValue();

				status = status | ADS_UF_ACCOUNTDISABLE;
				addModification(modList, entry, new LDAPAttribute("userAccountControl",
						Integer.toString(status)));

				lc.modify(entry.getDN(),
						(LDAPModification[]) modList.toArray(new LDAPModification[0]));
			}
		}
		catch (LDAPException e)
		{
			throw new InternalErrorException("ENTRY: " + entry.toString()
					+ " Error modifying user " + entry.getDN() + ": "
					+ e.toString(), e);
		}
	}

	/**
	 * Generar una dirección de correo a partir de alias y dominio
	 * 
	 * @param alias
	 *          Nombre a figurar a la izquierda de la arroba
	 * @param domain
	 *          Subdominio opcional a figurar a la derecha de la arroba
	 * @return dirección válida de correo
	 */
	private String textify (String alias, String domain)
	{
		if (domain == null && alias.indexOf("@") >= 0)
			return alias;
		else if (domain == null)
			return alias + "@caib.es";
		else
		{
			// Fem un cas especial si el domain conté .
			if (domain.indexOf(".") == -1)
				return alias + "@" + domain + ".caib.es";
			else
				// cas de domini principal distint a caib.es
				return alias + "@" + domain;
		}
	}

	/**
	 * Actualiza el mail de un usuario en el directorio LDAP.
	 * 
	 * @param user
	 *          código de usuario
	 * @throws InternalErrorException
	 * @see ActiveDirectoryAgent#UpdateUserAlias
	 */
	public void updateUserAlias (String user, Usuari ui)
			throws InternalErrorException
	{
		LDAPConnection lc = getConnection();
		synchronized (lc)
		{
			try
			{
				LDAPEntry entry = searchUser(user);
				ArrayList modList = new ArrayList();
				if (entry != null)
				{
					String dn = entry.getDN();
					if (ui.getNomCurt() != null)
					{
						LDAPAttribute atributo =
								new LDAPAttribute("mail", textify(ui.getNomCurt(),
										ui.getDominiCorreu()));
						modList
								.add(new LDAPModification(LDAPModification.REPLACE, atributo));
					}
					else
					{
						LDAPAttribute atributo = entry.getAttribute("mail");
						if (atributo != null)
							modList.add(new LDAPModification(LDAPModification.DELETE,
									atributo));
					}
					LDAPModification[] mods = new LDAPModification[modList.size()];
					mods = new LDAPModification[modList.size()];
					mods = (LDAPModification[]) modList.toArray(mods);
					lc.modify(dn, mods);
				}
			}
			catch (LDAPException e)
			{
				cerrarConexion();
				throw new InternalErrorException("Error LDAP", e);
			}
		}
	}

	public void removeUserAlias (String user) throws InternalErrorException
	{
		LDAPConnection lc = getConnection();
		synchronized (lc)
		{
			try
			{
				LDAPEntry entry = searchUser(user);
				if (entry != null)
				{
					String dn = entry.getDN();
					LDAPAttribute atributo = entry.getAttribute("mail");
					if (atributo != null)
					{
						LDAPModification[] modList =
								new LDAPModification[] { new LDAPModification(
										LDAPModification.DELETE, atributo) };
						lc.modify(dn, modList);
					}
				}
			}
			catch (LDAPException e)
			{
				cerrarConexion();
				throw new InternalErrorException("Error LDAP", e);
			}
		}
	}

	public void updateListAlias (LlistaCorreu llista) {}

	public void removeListAlias (String nomLlista, String domini) {}

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
		LDAPConnection lc = getConnection();
		synchronized (lc)
		{
			if (getDispatcher().getCodi().equals(rol.getBaseDeDades()))
			{
				log.info("Search grup {}@{} ", rol.getNom(), rol.getBaseDeDades());

				LDAPEntry grupoEntry = searchGroupEntry(rol.getNom());

				if (grupoEntry == null)
				{
					log.info("Adding group {} ", rol.getNom(), null);
					createGroupEntry(rol.getNom());
				}
				log.info("Updated role {} {}", rol.getNom(), rol.getBaseDeDades());
			}
		}
	}

	public void removeRole (String rolName, String dispatcher)
	{
		// No borrar
	}

	/**
	 * Busca el groupOfNames en el directorio LDAP
	 * 
	 * @param role
	 *          groupOfNames a buscar.
	 * @return LDAPEntry[] array de groupOfNames.
	 * @throws InternalErrorException
	 *           Error al buscar Roles
	 */
	private LDAPEntry searchGroupEntry (String group)
			throws InternalErrorException
	{
		try
		{
			LDAPEntry entry = new LDAPEntry();

			log.info("Looking for group {}", group, null);
			LDAPConnection lc = getConnection();
			synchronized (lc)
			{
				String searchFilter = "(&(objectClass=group)(sAMAccountName=" + escapeLDAPSearchFilter(group) + "))";
				int searchScope = LDAPConnection.SCOPE_SUB;
				LDAPSearchResults searchResults =
						lc.search(baseDN, searchScope, searchFilter, null, // return
																																		// all
								// attributes
								false); // return attrs and values
				if (searchResults.hasMore())
				{
					entry = searchResults.next();
				}
				else
				{
					entry = null;
				}
				while (searchResults.hasMore())
					searchResults.next();
			}

			if (entry == null)
				log.info("Not found", null, null);
			else
				log.info("Found", null, null);

			return (entry);
		}
		catch (LDAPException e)
		{
			cerrarConexion();
			throw new InternalErrorException("Error searching group " + group + ":"
					+ e.toString(), e);
		}
	}

	private LDAPEntry searchGroupMemberRange (String group, int rangeStart,
			int rangeEnd) throws InternalErrorException
	{
		try
		{
			log.info("Looking for group {}:{}", group, "member;Range=" + rangeStart
					+ "-" + rangeEnd);
			LDAPConnection lc = getConnection();
			synchronized (lc)
			{
				LDAPEntry entry = new LDAPEntry();
				String searchBase = "CN=Users, " + baseDN;
				String searchFilter = "(&(objectClass=group)(cn=" + escapeLDAPSearchFilter(group) + "))";
				int searchScope = LDAPConnection.SCOPE_ONE;
				LDAPSearchResults searchResults =
						lc.search(searchBase, searchScope, searchFilter,
								new String[] { "member;Range=" + rangeStart + "-" + rangeEnd }, // return
								// all
								// attributes
								false); // return attrs and values
				if (searchResults.hasMore())
				{
					entry = (LDAPEntry) searchResults.next();
				}
				else
				{
					entry = null;
				}
				while (searchResults.hasMore())
					searchResults.next();

				if (entry == null)
					log.info("Not found", null, null);
				else
					log.info("Found", null, null);

				return (entry);
			}
		}
		catch (LDAPException e)
		{
			cerrarConexion();
			throw new InternalErrorException("Error searching group " + group + ":"
					+ e.toString(), e);
		}
	}

	private LDAPEntry getGroupEntry (String group) throws InternalErrorException
	{
		// 1) Obtenemos el grupo
		LDAPEntry groupEntry = searchGroupEntry(group);
		if (groupEntry != null)
		{
			// Analizamos los atributos para ver si el número de miembros
			// requiere que realicemos diferentes consultas al servidor
			Vector<String> memberValues = new Vector<String>();
			LDAPEntry currentEntry = groupEntry;
			boolean repeat;
			do
			{
				repeat = false;
				// Omplir el vector de mebres
				LDAPAttributeSet atributos = currentEntry.getAttributeSet();
				for (Iterator it = atributos.iterator(); it.hasNext();)
				{
					LDAPAttribute attr = (LDAPAttribute) it.next();
					String nombre = attr.getName();
					if (nombre != null && nombre.toLowerCase().startsWith("member;range"))
					{
						int posIgual = nombre.indexOf("=");
						int posGuion = nombre.indexOf("-");
						if (posIgual != -1 && posGuion != -1)
						{
							String rangoIni = nombre.substring(posIgual + 1, posGuion);
							String rangoFin = nombre.substring(posGuion + 1);
							// Rellenar el vector
							for (Enumeration e = attr.getStringValues(); e.hasMoreElements();)
							{
								String value = (String) e.nextElement();
								memberValues.add(value);
							}
							// Eliminar l'attribut
							it.remove();
							// Localizar el siguiente
							if (!"*".equals(rangoFin))
							{ // Si no es el último
								int rangeStart = Integer.parseInt(rangoIni); // 0
								int rangeEnd = Integer.parseInt(rangoFin);// MAX_SERVER_RANGE_RETRIEVAL;
								// El rango inicial es 1
								currentEntry =
										searchGroupMemberRange(group, rangeEnd + 1, rangeEnd
												+ (rangeEnd - rangeStart));
								if (groupEntry != null)
									repeat = true;
							}
						}
					}
				}
			} while (repeat);
			if (memberValues.size() > 0)
			{
				String memberValuesArray[] =
						memberValues.toArray(new String[memberValues.size()]);
				LDAPAttribute newAttr = new LDAPAttribute("member", memberValuesArray);
				groupEntry.getAttributeSet().add(newAttr);
			}
		}

		return groupEntry;
	}

	/**
	 * Añade un nuevo groupOfNames en el directorio LDAP
	 * 
	 * @param rol
	 *          Información del groupOfNames a añadir
	 * @param users
	 *          Listado de members pertenecientes al groupOfNames rol
	 * @throws InternalErrorException
	 *           Error al añadir Roles
	 */
	private LDAPEntry createGroupEntry (String groupName)
			throws InternalErrorException
	{
		try
		{
			LDAPConnection lc = getConnection();
			synchronized (lc)
			{
				String dn = getGroupDN(groupName);
				LDAPAttributeSet attributeSet = new LDAPAttributeSet();
				attributeSet.add(new LDAPAttribute("objectclass", "group"));
				attributeSet.add(new LDAPAttribute("cn", groupName));
				attributeSet.add(new LDAPAttribute("sAMAccountName", groupName));
				LDAPEntry newEntry = new LDAPEntry(dn, attributeSet);
				lc.add(newEntry);
				return newEntry;
			}
		}
		catch (Exception e)
		{
			cerrarConexion();
			throw new InternalErrorException("Error adding group " + groupName
					+ ":" + e.toString(), e);
		}
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
		try
		{
			LDAPConnection lc = getConnection();
			synchronized (lc)
			{
				LDAPEntry entry = searchGroupEntry(group);
				if (entry != null)
				{
					String deleteDN = entry.getDN();
					lc.delete(deleteDN);
				}
			}
		}
		catch (LDAPException e)
		{
			cerrarConexion();
			throw new InternalErrorException("Error deleting group " + group + ":"
					+ e.toString(), e);
		}
	}

	private int getGroupSid (String group, LDAPConnection c) throws LDAPException
	{
		int id = -1;
		String searchBase = baseDN;
		String searchFilter = "(&(objectClass=group)(sAMAccountName=" + escapeLDAPSearchFilter(group) + "))";
		LDAPSearchResults searchResults =
				c.search(searchBase, LDAPConnection.SCOPE_ONE, searchFilter, null, // return
																																						// all
						// attributes
						false); // return attrs and values
		if (searchResults.hasMore())
		{
			LDAPEntry e = searchResults.next();
			LDAPAttribute att = e.getAttribute("objectSid");

			if (att != null)
			{
				byte b[] = att.getByteValue();
				for (int i = 0; i < b.length; i++)
				{
					System.out.print(" " + b[i]);
				}
				id = 0;
				for (int i = 0; i < 4; i++)
				{
					int j = b[b.length - i - 1];
					id = id * 256 + (j < 0 ? 256 + j : j);
				}
				System.out.print(" ID = " + id);
			}
			System.out.println("] ");
		}
		while (searchResults.hasMore())
			searchResults.next();
		return id;
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

	/**
	 * @param modList
	 */
	private LDAPModification addDeletion (ArrayList modList, LDAPEntry entry,
			String attribute)
	{
		LDAPAttribute att = entry.getAttribute(attribute);
		LDAPModification mod = null;
		if (att != null)
		{
			mod = new LDAPModification(LDAPModification.DELETE, att);
			modList.add(mod);
		}
		return mod;
	}

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

	public void removeGroup (String key) throws RemoteException,
			InternalErrorException
	{
		LDAPConnection lc = getConnection();
		synchronized (lc)
		{
			try
			{
				LDAPEntry grupoEntry = searchGroupEntry(key);
				if (grupoEntry != null)
					lc.delete(grupoEntry.getDN());
			}
			catch (LDAPException e)
			{
				throw new InternalErrorException(e.toString(), e);
			}
			finally
			{
				cerrarConexion();
			}
		}
	}

	public void updateGroup (String group, Grup gi) throws InternalErrorException
	{
		LDAPConnection lc = getConnection();
		synchronized (lc)
		{
			try
			{
				// UserInfo[] users = getServer().GetGroupUsersInfo(group,true);
				// //Eliminar
				log.info("Update grup {} ", group, null);

				LDAPEntry grupoEntry = searchGroupEntry(group);
				if (grupoEntry == null)
				{
					log.info("Adding group {} ", group, null);
					createGroupEntry(group);
				}
				log.info("Updated group {} ", group, null);
			}
			finally
			{
				cerrarConexion();
			}
		}
	}

	public void updateHost (Maquina maquina) throws RemoteException,
			InternalErrorException
	{
		if (maquina.getAdreca() == null || maquina.getAdreca().length() == 0)
			removeHost(maquina.getNom());
		else if (maquina.getSistemaOperatiu().equals("NTS")
				|| maquina.getSistemaOperatiu().equals("WTS")
				|| maquina.getSistemaOperatiu().equals("NTW"))
		{
			String host = maquina.getNom();
			LDAPEntry entry = searchHost(host);
			if (entry == null)
			{
				// Mirem si és un domain-controller
				entry = searchHostDC(host);
				if (entry != null)
				{
					log.info("Host found '{}' as a Domain Controller", host,
							null);
					return; // no hem de fer res..
				}
			}
			if (entry == null)
			{// Es nuevo
				addHost(maquina);
			}
			else
			{// Es una actualización:
				// cambiamos el grupo(xarxa) a la que pertenece
				LDAPAttribute memberOf = entry.getAttribute("memberOf");
				if (memberOf != null)
				{
					String grupXarxaAnterior = (String) memberOf.getStringValue();
					String grupXarxaActual =
							getComputerGroupDN("xarxa" + maquina.getCodiXarxa());
					// Verificamos que el grupo al que pertenece corresponde a
					// su xarxa y si no es así, lo corregimos
					if (!LDAPDN.equals(grupXarxaAnterior, grupXarxaActual))
					{
						try
						{
							// Lo borramos del anterior y la añadimos al nuevo
							String maquinaGroup = getComputerGroupDN(host);

							LDAPConnection c = getConnection();
							synchronized (c)
							{

								c.modify(grupXarxaAnterior, new LDAPModification(
										LDAPModification.DELETE, new LDAPAttribute("member",
												maquinaGroup)));
								c.modify(grupXarxaActual, new LDAPModification(
										LDAPModification.ADD, new LDAPAttribute("member",
												maquinaGroup)));
							}
						}
						catch (LDAPException e)
						{
							cerrarConexion();
							throw new InternalErrorException("Error creating role " + host
									+ ":" + e.toString(), e);
						}
					}
				}
				else
				{// CASO ESPECIAL:
					// Cubrimos el caso en que NO PERTENECE a NINGÚN GRUPO
					// Lo tratamos como si fuera nuevo (y lo añadimos/creamos el
					// grupo)
					// ¿Ya existe el grupo?
					LDAPEntry grupoMaquina =
							searchComputerGroup("xarxa" + maquina.getCodiXarxa());
					if (grupoMaquina == null)
					{ // No existe: lo creamos
						// Creamos un nuevo grupo para la máquina si no existe
						grupoMaquina = addComputerGroup("xarxa" + maquina.getCodiXarxa());
					}
					// Le añadimos el atributo "miembro de" al grupo para esta
					// máquina
					// Añadimos el atributo miembro al grupo anterior
					else
					{
						try
						{
							// Añadimos un nuevo miembro al grupo
							LDAPConnection c = getConnection();
							synchronized (c)
							{
								c.modify(
										grupoMaquina.getDN(),
										new LDAPModification[] { new LDAPModification(
												LDAPModification.ADD, new LDAPAttribute("member", entry
														.getDN())) });
							}
						}
						catch (LDAPException e)
						{
							cerrarConexion();
							throw new InternalErrorException("Error creating host " + host
									+ " :" + e.toString(), e);
						}
					}
				}
			}
		}
		else
		{
			removeHost(maquina.getNom());
		}
	}

	public void removeHost (String name) throws RemoteException,
			InternalErrorException {}

	/**
	 * Cerca les dades d'una màquina en el directori LDAP
	 * 
	 * @param user
	 *          codigo de host
	 * @return LDAPEntry entrada del directorio LDAP
	 * @throws InternalErrorException
	 *           Error al buscar el host
	 */
	private LDAPEntry searchHost (String host) throws InternalErrorException
	{
		try
		{
			log.info("searchHost {} ", host, null);
			LDAPConnection lc = getConnection();
			synchronized (lc)
			{
				LDAPEntry entry = new LDAPEntry();
				String searchBase = "CN=Computers, " + baseDN;
				String searchFilter = "(&(objectClass=computer)(cn=" + host + "))";
				int searchScope = LDAPConnection.SCOPE_ONE;
				LDAPSearchResults searchResults =
						lc.search(searchBase, searchScope, searchFilter, null, // return all
								// attributes
								false); // return attrs and values
				if (searchResults.hasMore())
				{
					entry = searchResults.next();
				}
				else
				{
					entry = null;
				}
				while (searchResults.hasMore())
					searchResults.next();
				return (entry);
			}
		}
		catch (Exception e)
		{
			cerrarConexion();
			throw new InternalErrorException("Error searching host " + host + ":"
					+ e.toString(), e);
		}
	}

	/**
	 * Cerca les dades d'una màquina tipus Domain Controller en el directori LDAP
	 * 
	 * @param user
	 *          codigo de host
	 * @return LDAPEntry entrada del directorio LDAP
	 * @throws InternalErrorException
	 *           Error al buscar el host
	 */
	private LDAPEntry searchHostDC (String host) throws InternalErrorException
	{
		try
		{
			log.info("searchHost {} ", host, null);
			LDAPConnection lc = getConnection();
			synchronized (lc)
			{
				LDAPEntry entry = new LDAPEntry();
				String searchBase = "OU=Domain Controllers, " + baseDN;
				String searchFilter = "(&(objectClass=computer)(cn=" + escapeLDAPSearchFilter(host) + "))";
				int searchScope = LDAPConnection.SCOPE_ONE;
				LDAPSearchResults searchResults =
						lc.search(searchBase, searchScope, searchFilter, null, // return all
								// attributes
								false); // return attrs and values
				if (searchResults.hasMore())
				{
					entry = searchResults.next();
				}
				else
				{
					entry = null;
				}
				while (searchResults.hasMore())
					searchResults.next();
				return (entry);
			}
		}
		catch (Exception e)
		{
			cerrarConexion();
			throw new InternalErrorException("Error searching host " + host + ":"
					+ e.toString(), e);
		}
	}

	/**
	 * Encontramos los grupos a los que pertenece el host Para poder eliminar la
	 * pertenencia a estos grupos cuando se elimine el grupo
	 * 
	 * @param host
	 * @return
	 * @throws InternalErrorException
	 */
	/*
	 * private LDAPEntry searchGroupsHostIsMember(String host) throws
	 * InternalErrorException {//u88683 try
	 * {//(&(objectclass=group)(member=CN=pruebamaq004
	 * ,CN=Computers,DC=caib,DC=es)) LDAPConnection lc = getConnection();
	 * LDAPEntry entry = new LDAPEntry(); String searchBase = "cn=Computers, " +
	 * baseDN; String searchFilter = "(objectClass=group)"; int searchScope =
	 * LDAPConnection.SCOPE_ONE; LDAPSearchResults searchResults =
	 * lc.search(searchBase, searchScope, searchFilter, new String[]
	 * {"(member=cn=" + host +","+ searchBase +")"}, // return all attributes
	 * false); // return attrs and values if (searchResults.hasMore()) { entry =
	 * searchResults.next(); } else { entry = null; } while
	 * (searchResults.hasMore()) searchResults.next(); return (entry); } catch
	 * (Exception e) { cerrarConexion(); throw new
	 * InternalErrorException("Error al buscar el host " + host + ":" +
	 * e.toString()); } }
	 */

	/**
	 * Genera el nombre del grupo para la Red da la Máquina
	 * 
	 * @param group
	 * @return
	 */
	private String getComputerGroupDN (String group)
	{// u88683
		return "cn=" + group + ", cn=Computers, " + baseDN;
	}

	/**
	 * Busca el grupo que almacena los hosts
	 * 
	 * @param group
	 * @return
	 * @throws InternalErrorException
	 */
	private LDAPEntry searchComputerGroup (String group)
			throws InternalErrorException
	{// u88683

		try
		{
			LDAPConnection lc = getConnection();
			synchronized (lc)
			{
				LDAPEntry entry = new LDAPEntry();
				String searchBase = "CN=Computers, " + baseDN;
				String searchFilter = "(&(objectClass=group)(cn=" + escapeLDAPSearchFilter(group) + "))";
				int searchScope = LDAPConnection.SCOPE_ONE;
				LDAPSearchResults searchResults =
						lc.search(searchBase, searchScope, searchFilter, null, // return all
								// attributes
								false); // return attrs and values
				if (searchResults.hasMore())
				{
					entry = searchResults.next();
				}
				else
				{
					entry = null;
				}
				while (searchResults.hasMore())
					searchResults.next();
				return (entry);
			}
		}
		catch (Exception e)
		{
			cerrarConexion();
			throw new InternalErrorException("Error searching the host group "
					+ group + ":" + e.toString(), e);
		}
	}

	/**
	 * Método que se encarga de crear un grupo para la máquina
	 * 
	 * @param groupName
	 * @return
	 * @throws InternalErrorException
	 */
	private LDAPEntry addComputerGroup (String groupName)
			throws InternalErrorException
	{// u88683
		try
		{
			LDAPConnection lc = getConnection();
			synchronized (lc)
			{
				String dn = getComputerGroupDN(groupName);
				LDAPAttributeSet attributeSet = new LDAPAttributeSet();
				attributeSet.add(new LDAPAttribute("objectclass", "group"));
				attributeSet.add(new LDAPAttribute("cn", groupName));
				attributeSet.add(new LDAPAttribute("sAMAccountName", groupName));
				LDAPEntry newEntry = new LDAPEntry(dn, attributeSet);
				lc.add(newEntry);
				return newEntry;
			}
		}
		catch (Exception e)
		{
			cerrarConexion();
			throw new InternalErrorException("Error adding group to host "
					+ groupName + ":" + e.toString(), e);
		}
	}

	/**
	 * Añade los datos de una máquina al directorio LDAP
	 * 
	 * @param hi
	 *          Información de la máquina
	 * @throws InternalErrorException
	 *           Error al añadir el usuario al directorio LDAP
	 */
	private void addHost (Maquina hi) throws InternalErrorException
	{
		try
		{// Añadimos un grupo para contener los hosts : u88683
			log.info("addHost {} ", hi != null ? hi.getNom() : "", null);

			String dn = "cn=" + hi.getNom() + ", cn=Computers, " + baseDN;

			// Buscamos el grupo al que debe pertenecer el host.
			// Si no existe el grupo para la xarxa lo creamos.
			// NOTA: Para evitar que se repitan los grupos (da error si ya
			// existen
			// los grupos aunque sean dentro de Users), se añade
			// xarxaNOMBREXARXA
			LDAPEntry grupoMaquina = searchComputerGroup("xarxa" + hi.getCodiXarxa());
			if (grupoMaquina == null)
			{
				grupoMaquina = addComputerGroup("xarxa" + hi.getCodiXarxa());// Creamos
				// un
				// nuevo
				// grupo para la
				// máquina
			}

			// Alta de la máquina
			LDAPConnection lc = getConnection();
			synchronized (lc)
			{
				LDAPAttributeSet attributeSet = new LDAPAttributeSet();
				attributeSet.add(new LDAPAttribute("objectclass",
						new String[] { "computer" }));
				attributeSet.add(new LDAPAttribute("cn", new String[] { hi.getNom() }));
				attributeSet
						.add(new LDAPAttribute("sAMAccountName", hi.getNom() + "$"));
				attributeSet.add(new LDAPAttribute("userAccountControl", Integer
						.toString(ADS_UF_WORKSTATION_TRUST_ACCOUNT)));

				LDAPEntry newEntry = new LDAPEntry(dn, attributeSet);
				lc.add(newEntry);
				// Añadimos el atributo miembro al grupo anterior
				if (grupoMaquina != null && newEntry != null)
				{
					// Añadimos un nuevo miembro al grupo
					lc.modify(
							grupoMaquina.getDN(),
							new LDAPModification[] { new LDAPModification(
									LDAPModification.ADD, new LDAPAttribute("member", newEntry
											.getDN())) });
				}
			}
		}
		catch (LDAPException e)
		{
			cerrarConexion();
			throw new InternalErrorException("Error creating host " + hi.getNom()
					+ ":" + e.toString(), e);
		}
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
			LDAPEntry entry = searchUser(uid);
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
							.add(new LDAPAttribute("servicePrincipalName", result.getPrincipalName()));
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
		log.debug("Updating account [%s]", user);
		Usuari fakeUsuari = new Usuari();
		fakeUsuari.setCodi(user);
		fakeUsuari.setCodiGrupPrimari("");
		fakeUsuari.setFullName(description);
		fakeUsuari.setActiu(Boolean.TRUE);
		LDAPEntry usuario;
		log.info("Search user {} ", user, null);
		usuario = searchUser(user);
		if (usuario == null)
		{
			log.info("Adding user {} ", user, null);
			addUser(user, fakeUsuari);
			usuario = searchUser(user);
		}
		if (usuario != null)
		{
			log.info("Update user data {} ", user, null);
			try
			{
				int status = 0;
				LDAPAttribute att = usuario.getAttribute("userAccountControl");

				if (att != null)
				{
					status = Integer.decode(att.getStringValue()).intValue();
					// Si el usuario estaba desactivado y se vuelve
					// a activar se le asigna una contraseña aleatoria
					// para evitar error en Windows
					if (status != 0
							&& (status & ADS_UF_ACCOUNTDISABLE) == ADS_UF_ACCOUNTDISABLE)
					{
						try
						{
							// Asignamos una contraseña aleatoria y hacemos
							// que la cambie cuando se conecte el usuario
							Password pass =
									getServer().getOrGenerateUserPassword(user, getCodi());
							updateUserPassword(user, fakeUsuari, pass, true);
							// Activamos el usuario (como cuando se crea de
							// nuevo)
							LDAPAttribute att_reactiva =
									new LDAPAttribute("userAccountControl",
											Integer.toString(ADS_UF_NORMAL_ACCOUNT));
							LDAPModification mod_reactiva =
									createModification(usuario, att_reactiva);
							LDAPConnection lc = getConnection();
							synchronized (lc)
							{
								lc.modify(usuario.getDN(), mod_reactiva);
							}
						}
						catch (RemoteException e)
						{
							cerrarConexion();
						}
					}
				}
			}
			catch (Exception ex)
			{
				log.warn("Error updating account", ex);
			}
			// Modifica los datos de la entrada de un usuario del directorio
			// LDAP:
			updateAccountGroups(user, usuario);
		}
		log.info("Updated user {} ", user, null);
	}

	private void updateAccountGroups (String user, LDAPEntry usuario)
			throws RemoteException, InternalErrorException
	{
		// Aquí llegamos en usuarios nuevos y existentes ACTIVOS
		// Gestionamos la membresía del usuario a roles y grupos
		// en el atributo member-of del usuario lo tenemos
		LDAPAttribute memberofattr = usuario.getAttribute("memberOf");
		String grupsCAIBUsuari[] =
				memberofattr == null ? new String[] {} : memberofattr
						.getStringValueArray();
		HashSet<String> h_grupsCAIBUsuari = new HashSet(); // caib
		for (int i = 0; i < grupsCAIBUsuari.length; i++)
		{
			log.info("User {} belongs to [{}]", user, extractCN(grupsCAIBUsuari[i]));
			h_grupsCAIBUsuari.add(extractCN(grupsCAIBUsuari[i]).toLowerCase());
		}
		try
		{
			HashSet<String> groups = new HashSet<String>();
			for (RolGrant grant : getServer().getAccountRoles(user, getCodi()))
			{
				if (!groups.contains(grant.getRolName()))
					groups.add(grant.getRolName());
			}
			for (Iterator<String> it = groups.iterator(); it.hasNext();)
			{
				String group = it.next();
				log.info("User {} should belong to [{}]", user, group);
				if (!h_grupsCAIBUsuari.remove(group.toLowerCase()))
				{
					addGroupMember(group, user, usuario);
				}
			}
			// Esborram dels grups excedents
			for (Iterator it = h_grupsCAIBUsuari.iterator(); it.hasNext();)
			{
				String grup = (String) it.next();
				removeGroupMember(grup, user, usuario);
			}
		}
		catch (LDAPException e)
		{
			throw new InternalErrorException("Error updating groups", e);
		}
	}

	/**
	 * Modifica los datos de la entrada de un usuario del directorio LDAP
	 * 
	 * @param usuario
	 *          Entrada LDAP del usuario a modificar
	 * @param ui
	 *          Informacion del usuario a modificar en el seycon
	 * @throws InternalErrorException
	 *           Error al modificar el usuario al directorio LDAP
	 */
	private void updateAccountData (LDAPEntry usuario, String user,
			String description) throws InternalErrorException
	{
		try
		{
			log.info("Updating user {} data", user, null);
			LDAPConnection lc = getConnection();
			synchronized (lc)
			{
				ArrayList modList = new ArrayList();
				ArrayList modListUserAccount = new ArrayList();

				addModification(modList, usuario, new LDAPAttribute("description",
						description));

				// Modificación del atributo userAccountControl:
				int status = 0;
				LDAPAttribute att = usuario.getAttribute("userAccountControl");

				if (att != null)
					status = Integer.decode(att.getStringValue()).intValue();

				// Quitar el disable
				status = status & (~ADS_UF_ACCOUNTDISABLE);
				// Quitar el lockout
				status = status & (~ADS_UF_LOCKOUT);
				// Quitar el flag de nunca caducar passwd
				status = status & (~ADS_UF_DONT_EXPIRE_PASSWD);
				// Poner estado de cuenta normal
				status = status | ADS_UF_NORMAL_ACCOUNT;

				// Añadimos esta modificación en una lista diferente
				addModification(modListUserAccount, usuario, new LDAPAttribute(
						"userAccountControl", Integer.toString(status)));

				// Intentamos hacer la modificación del userAccountControl
				// Esta puede fallar en el caso de que la contraseña actual
				// del usuario no sea correcta, por eso se hace por separado
				try
				{
					lc.modify(usuario.getDN(), (LDAPModification[]) modListUserAccount
							.toArray(new LDAPModification[0]));
				}
				catch (LDAPException lex)
				{
					// Analizamos la excepción, para ver si es por problemas de
					// contraseñas en tal caso el resultcode es
					// UNWILLING_TO_PERFORM

					if (lex.getResultCode() == LDAPException.UNWILLING_TO_PERFORM)
					{
						// Reseteamos la contraseña del usuario:
						// Asignamos una contraseña aleatoria y hacemos
						// que la cambie cuando se conecte el usuario
						// También se modifica el "userAccountControl"
						Password pass = getServer().generateFakePassword(user, getCodi());
						try
						{
							updateIncorrectPassword(usuario, user, null, pass, false, status);
						}
						catch (LDAPException e)
						{
							if (LDAPException.ATTRIBUTE_OR_VALUE_EXISTS == e.getResultCode())
							{
								try
								{
									updateIncorrectPassword(usuario, user, null, pass, true,
											status);
								}
								catch (LDAPException exception)
								{
									cerrarConexion();
									throw new InternalErrorException(
											"Error changing password:" + exception.getMessage(),
											exception);
								}
							}
							else
							{
								cerrarConexion();
								throw new InternalErrorException("Error changing password:"
										+ e.getMessage(), e);
							}
						}
					}
				}

				// Para ver qué modificación da error: TRAZAS u88683
				/*
				 * for (int i=0; i < modList.size(); i++) { try { LDAPModification mod =
				 * (LDAPModification) modList.get(i); lc.modify(entry.getDN(),mod); }
				 * catch (LDAPException exc) { String resultCode =
				 * exc.resultCodeToString(); throw new InternalErrorException
				 * ("<br><b>Error modificando entrada LDAP: "
				 * +" entrada: ("+(LDAPModification)
				 * modList.get(i)+")</b><br>Error causado = "+exc.toString()); } }
				 */

				// Esborrem attribut scriptPath, si existeix
				addDeletion(modList, usuario, "scriptPath");

				// Hacemos el resto de modificaciones
				lc.modify(usuario.getDN(),
						(LDAPModification[]) modList.toArray(new LDAPModification[0]));
			}
		}
		catch (LDAPException e)
		{
			throw new InternalErrorException("Entry: " + usuario.toString()
					+ " Error modifying user " + user + ": " + e.toString(), e);
		}
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
				String searchFilter =
						"(&(objectClass=user)(!(objectClass=computer))(sAMAccountName=*))";
				int searchScope = LDAPConnection.SCOPE_SUB;
				LDAPPagedResultsControl pageResult =
						new LDAPPagedResultsControl(lc.getSearchConstraints()
							.getMaxResults(), false);

				do
				{
					LDAPSearchConstraints constraints = lc.getSearchConstraints();
					constraints.setControls(pageResult);
					lc.setConstraints(constraints);

					LDAPSearchResults searchResults = lc.search(baseDN, searchScope,
							searchFilter, null,	// return all attributes
							false);	// return attrs and values

					// Process results
					while (searchResults.hasMore())
					{
						entry = searchResults.next();

						userAccounts.add(entry.getAttribute("sAMAccountName").getStringValue());
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
			LDAPEntry entry = searchUser(userAccount);

			userInfo.setCodi(entry.getAttribute("sAMAccountName").getStringValue());

			// Check user name
			if ((entry.getAttribute("givenName") != null)
					&& (entry.getAttribute("sn") != null))
			{
				userInfo.setNom(entry.getAttribute("givenName").getStringValue());
				userInfo.setPrimerLlinatge(entry.getAttribute("sn").getStringValue());
			}

			else
			{
				userInfo.setNom(getUserFullName(entry));
			}
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
		LinkedList<String> rolesNames = null; // Roles names
		String base = "Users"; // Base tree

		try
		{
			do
			{
				if (rolesNames != null)
				{
					base = "Builtin";
				}

				else
				{
					rolesNames = new LinkedList<String>();
				}

				LDAPConnection lc = getConnection();
				synchronized (lc)
				{
					LDAPEntry entry = null;
					String searchBase = String.format("CN=%s, %s", base, baseDN);
					String searchFilter = "(&(objectClass=Group)(sAMAccountName=*))";
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

							rolesNames.add(entry.getAttribute("sAMAccountName").getStringValue());
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
			} while (!base.equals("Builtin"));
		}

		catch (LDAPException e)
		{
			cerrarConexion();

			throw new InternalErrorException(String.format(
					"Error to find groups: %s", e.toString()), e);
		}

		return rolesNames;
	}

	/*
	 * (non-Javadoc)
	 * @see
	 * es.caib.seycon.ng.sync.intf.ReconcileMgr#getRoleFullInfo(java.lang.String )
	 */
	public Rol getRoleFullInfo (String roleName) throws RemoteException,
			InternalErrorException
	{
		Rol roleInfo = new Rol(); // Role info

		try
		{
			LDAPEntry entry = getGroupEntry(roleName);

			roleInfo.setNom(entry.getAttribute("sAMAccountName").getStringValue());
			roleInfo.setDescripcio(getRoleDescription(entry));
		}

		catch (Exception e)
		{
			cerrarConexion();

			String msg = String.format("Error to obtain group '%s' data:", roleName);
			log.warn(msg, e);
			throw new InternalErrorException(msg + e.toString(), e);
		}

		return roleInfo;
	}

	/**
	 * Implements the functionality to obtain the role description.
	 * 
	 * <p>
	 * If the role does not have description, the description returned will be the
	 * sAMAccountName role value.
	 * 
	 * @param entry
	 *          LDAP entry to obtain the role description.
	 * @return String that contains the role description.
	 */
	private String getRoleDescription (LDAPEntry entry)
	{
		String roleDesc; // Role description

		// Check existing role description
		if (entry.getAttribute("description") != null)
		{
			roleDesc = entry.getAttribute("description").getStringValue();
		}

		else
		{
			roleDesc = entry.getAttribute("CN").getStringValue();
		}

		return roleDesc;
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
		Rol userRole; // User role
		LinkedList<Rol> rolesList = new LinkedList<Rol>(); // User roles
		LDAPEntry userEntry = searchUser(userAccount); // User LDAP entry data
		LDAPAttribute memberofattr; // User LDAP groups
		String userGroups[]; // User group array

		memberofattr = userEntry.getAttribute("memberOf");
		userGroups =
				(memberofattr == null ? new String[] {} : memberofattr
						.getStringValueArray());

		// Process the user groups
		for (int i = 0; i < userGroups.length; i++)
		{
			log.info("User {} belongs to [{}]", userAccount, extractCN(userGroups[i]));

			userRole = getRoleFullInfo(extractCN(userGroups[i]));

			rolesList.add(userRole);
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

	public String parseKerberosToken(String serverPrincipal, byte[] keytab, byte[] token)
			throws InternalErrorException {
		// TODO Auto-generated method stub
		return null;
	}

}
