package com.soffid.iam.sync.agent2;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.rmi.RemoteException;
import java.util.ArrayList;
import java.util.Iterator;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPModification;

import es.caib.seycon.ng.comu.ObjectMappingTrigger;
import es.caib.seycon.ng.comu.Password;
import es.caib.seycon.ng.comu.Rol;
import es.caib.seycon.ng.comu.RolGrant;
import es.caib.seycon.ng.comu.SoffidObjectTrigger;
import es.caib.seycon.ng.comu.SoffidObjectType;
import es.caib.seycon.ng.config.Config;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownRoleException;
import es.caib.seycon.ng.sync.engine.Watchdog;
import es.caib.seycon.ng.sync.engine.extobj.GrantExtensibleObject;
import es.caib.seycon.ng.sync.intf.ExtensibleObject;
import es.caib.seycon.ng.sync.intf.ExtensibleObjectMapping;
import es.caib.seycon.util.TimedProcess;

public class CustomizableNativeActiveDirectoryAgent extends CustomizableActiveDirectoryAgent 
{

	private static final String EXE_NAME = "usradm-2.0.1.exe";
	static final String DLL_NAME = "libwinpthread-1.dll";
	private String suffix;
	private String samAccountName;



	public CustomizableNativeActiveDirectoryAgent() throws RemoteException {
		super();
		useSsl = false;
		ldapPort = LDAPConnection.DEFAULT_PORT;
	}

	
	
	@Override
	public void init() throws InternalErrorException {
		super.init();
		
		try {
			LDAPEntry entry;
			if (loginDN.contains("\\"))
			{
				ExtensibleObject eo = new ExtensibleObject();
				eo.setObjectType(SoffidObjectType.OBJECT_ACCOUNT.getValue());
				eo.setAttribute("objectClass", "user");
				String s = loginDN.substring(loginDN.indexOf('\\')+1);
				entry = searchSamAccount(eo, s);
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
			}
			if (entry == null)
				throw new InternalErrorException("Unable to locate administrator account ("+loginDN+","+baseDN+") in LDAP server");

			LDAPAttribute att = entry.getAttribute(SAM_ACCOUNT_NAME_ATTRIBUTE);
			if (att == null)
				throw new InternalErrorException("It's weird, but administrator account has no sAMAccountName attribute");
			
			if (File.separatorChar == '/')
			{
				samAccountName = att.getStringValue();
				for (String part: entry.getDN().split(","))
				{
					if (part.toLowerCase().startsWith("dc="))
					{
						samAccountName = part.substring(3)+"\\"+samAccountName;
						break;
					}
						
				}
			} 
			else
			{
				suffix = " --user \"" + att.getStringValue() + "\" --password \"" + password.getPassword()
					+ "\" -S \"" + getRealmName() + "\"";
			} 
			
			File f = new File(Config.getConfig().getHomeDir(), "system/" + EXE_NAME);
			extractSystemFile("usradm.exe", f);
			extractSystemFile(DLL_NAME, new File(Config.getConfig().getHomeDir(),
					"system/" + DLL_NAME));

		} catch (Exception e) {
			throw new InternalErrorException(
					"Cannot connect to active directory", e);
		}
		
	}

	private void extractSystemFile(String resourceName, File f)
			throws FileNotFoundException, IOException {
		if (!f.canRead()) {
			String rsrc = "com/soffid/iam/sync/agent/native/"+resourceName;
			InputStream in = getClass().getClassLoader().getResourceAsStream(
					rsrc);
			if (in == null)
				throw new IOException("Unable to find resource "+rsrc);
			FileOutputStream out = new FileOutputStream(f);
			int i = in.read();
			while (i >= 0) {
				out.write(i);
				i = in.read();
			}
			in.close();
			out.close();
		}
	}


	protected void performPasswordChange(LDAPEntry ldapUser, String accountName,
			Password password, boolean mustchange, boolean delegation,
			boolean replacePassword) throws Exception {
		
		TimedProcess p;
		try {
			// Comprobar si el usuario existe
			p = new TimedProcess(4000);
			if (File.separatorChar == '\\')
			{
				int result = p.exec(EXE_NAME + " -i " + accountName + " -q" + suffix);
				// Si el usuario no existe -> Error interno
				if (result != 0) {
					throw new InternalErrorException("Unknown user" + accountName);
				}
				String args = EXE_NAME + " -u \"" + accountName + "\" -p \""
						+ password.getPassword() + "\"";
				if (mustchange)
					args = args + " -Fx"; // Activa con cambio de contraseña
				else
					args = args + " -F"; // Activa y válida
				args = args + " -q";
				result = p.exec(args + suffix);
			} else {
				int result = p.exec(new String[] {
						"net",
						"rpc",
						"user",
						"password",
						accountName,
						password.getPassword(),
						"-U",
						samAccountName+"%"+this.password.getPassword(),
						"-S",
						this.ldapHost
				});
				// Si el usuario no existe -> Error interno
				if (result != 0) {
					throw new InternalErrorException("Error setting password for " + accountName+"\n"+
							p.getOutput()+"\n"+p.getError());
				}
				performLDAPPasswordChange(ldapUser, accountName, mustchange, delegation, replacePassword);
			}
		} catch (Exception e) {
			throw new InternalErrorException(e.toString());
		}
	}


	protected void performLDAPPasswordChange(LDAPEntry ldapUser, String accountName,
			boolean mustchange, boolean delegation,
			boolean replacePassword) throws Exception {
		ArrayList<LDAPModification> modList = new ArrayList<LDAPModification>();
		LDAPAttribute atributo;
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

		LDAPModification[] mods = new LDAPModification[modList.size()];
		mods = (LDAPModification[]) modList.toArray(mods);
		debugModifications("Modifying password ", ldapUser.getDN(), mods);
		String domain = searchDomainForDN (ldapUser.getDN());
		try {
			getConnection(domain).modify(ldapUser.getDN(), mods);
		} finally {
			returnConnection(domain);
		}
		log.info("UpdateUserPassword - setting password for user {}",
				accountName, null);
	}


}
