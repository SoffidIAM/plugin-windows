// Copyright (c) 2000 Govern  de les Illes Balears
// $Log: WindowsNTWAgent.java,v $
// Revision 1.3  2012-11-05 07:42:42  u07286
// Nova versió interfície
//
// Revision 1.2  2012-06-13 13:05:31  u88683
// - Nous usuaris: propaguem la contrasenya (ActiveDirectori, WindowsNTPDCAgent, WindowsNTWAgent)
// - Ho fem compatible amb seycon-base-4.0.4 (nous paquets)
//
// Revision 1.1  2012-02-14 07:03:16  u07286
// Versió inicial
//
// Revision 1.1  2007-09-06 12:51:10  u89559
// [T252]
//
// Revision 1.4  2005-08-10 08:37:14  u07286
// Cambiado mecanismo de confianza en el servidor
//
// Revision 1.3  2004/03/15 12:08:09  u07286
// Conversion UTF-8
//
// Revision 1.2  2004/03/15 11:57:54  u07286
// Agregada documentacion JavaDoc
//

package com.soffid.iam.sync.agent;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.rmi.RemoteException;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import es.caib.seycon.*;
import es.caib.seycon.agent.WindowsNTAgent;
import es.caib.seycon.ng.comu.Account;
import es.caib.seycon.ng.comu.AccountType;
import es.caib.seycon.ng.comu.Grup;
import es.caib.seycon.ng.comu.Password;
import es.caib.seycon.ng.comu.Rol;
import es.caib.seycon.ng.comu.RolGrant;
import es.caib.seycon.ng.comu.Usuari;
import es.caib.seycon.ng.config.Config;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownRoleException;
import es.caib.seycon.ng.sync.agent.Agent;
import es.caib.seycon.ng.sync.intf.ReconcileMgr2;
import es.caib.seycon.ng.sync.intf.RoleMgr;
import es.caib.seycon.ng.sync.intf.UserMgr;
import es.caib.seycon.util.TimedOutException;
import es.caib.seycon.util.TimedProcess;

/**
 * Implementa el agente para estaciones de trabajo Windows NT. También es
 * aplicable a servidores NT miembros de dominio. Su utilización es básicamente
 * para entornos de test
 * <P>
 * 
 * @author $Author: u07286 $
 * @versin $Revision: 1.3 $
 */
public class RemoteWindowsAgent extends Agent implements UserMgr,
		ReconcileMgr2, RoleMgr {
	Log log = LogFactory.getLog(getClass());

	static final String EXE_NAME = "usradm-2.0.0.exe";
	static final String DLL_NAME = "libwinpthread-1.dll";

	static final String NET_NAME = "net";
	static final String NETAPI_NAME = "libnetapi.so.0";

	private static final String LIBRARY_PATH = "/usr/lib/x86_64-linux-gnu/samba/:/usr/lib/i386-linux-gnu/samba/";

	String serverName;
	String nbServerName;
	String suffix;
	String suffix2;
	boolean isWindows;

	private String[] environment;

	/**
	 * Constructor
	 */
	public RemoteWindowsAgent() throws java.rmi.RemoteException {
	}

	@Override
	public void init() throws InternalErrorException {
		isWindows = File.separatorChar == '\\';

		serverName = getDispatcher().getParam0();
		if (getDispatcher().getParam0() == null
				|| getDispatcher().getParam0().trim().length() == 0)
			throw new InternalErrorException("server name is empty");

		if (getDispatcher().getParam1() == null
				|| getDispatcher().getParam1().trim().length() == 0)
			throw new InternalErrorException("server name is empty");

		if (getDispatcher().getParam1() == null
				|| getDispatcher().getParam1().trim().length() == 0)
			throw new InternalErrorException("server name is empty");

		String user = getDispatcher().getParam1();
		Password p = Password.decode(getDispatcher().getParam2());

		if (isWindows)
			suffix = " --user \"" + user + "\" --password \"" + p.getPassword()
					+ "\" -S \"" + serverName + "\"";
		else
		{
			suffix = "-U"+ user + "%" + p.getPassword();
			suffix2 = "-S"+ serverName ;
		}

		try {
			Config config = Config.getConfig();
			if (isWindows) {
				File f = new File(config.getHomeDir(), "system/" + EXE_NAME);
				extractSystemFile("usradm.exe", f);
				extractSystemFile(DLL_NAME, new File(config.getHomeDir(),
						"system/" + DLL_NAME));
			} else {
				File f = new File(config.getHomeDir(),"system/" + NET_NAME);
				extractSystemFile(NET_NAME, f);
				TimedProcess tp = new TimedProcess(3000);
				int result = tp.exec(new String[] {"chmod","755",f.getPath()});
				if (result != 0) {
					throw new InternalErrorException("Error setting attributes for "+NET_NAME+":\n"+
							tp.getOutput()+"\n"+tp.getError());
				}
				extractSystemFile(NETAPI_NAME, new File(config.getHomeDir(),
						"system/" + NETAPI_NAME));
				generateEnvironment();
				getNbServerName ();
			}
		} catch (IOException e) {
			throw new InternalErrorException("Error extracting files");
		} catch (TimedOutException e) {
			throw new InternalErrorException("Error extracting files", e);
		}

	}

	private void generateEnvironment() {
		Map<String, String> env = System.getenv();
		LinkedList<String> env2 = new LinkedList<String>();
		for (String key : env.keySet())
		{
			if (!key.equals ("LD_LIBRARY_PATH"))
				env2.add(key+"="+env.get(key));
		}
				
		String library_path = System.getenv("LD_LIBRARY_PATH");
		if (library_path == null)
			env2.add ("LD_LIBRARY_PATH=/usr/lib:/lib"+LIBRARY_PATH);
		else
			env2.add ("LD_LIBRARY_PATH="+LIBRARY_PATH+":"+library_path);
		environment = env2.toArray(new String[env2.size()]);
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

	/**
	 * Actualizar la contraseña del usuario
	 */
	public void updateUserPasswordWindows(String user, Usuari ui,
			Password password, boolean mustchange)
			throws java.rmi.RemoteException, InternalErrorException {
		TimedProcess p;
		try {
			// Comprobar si el usuario existe
			p = new TimedProcess(4000);
			int result = p.exec(EXE_NAME + " -i " + user + " -q" + suffix);
			// Si el usuario no existe -> Error interno
			if (result != 0) {
				throw new InternalErrorException("Usuario no existente " + user);
			}
			String args = EXE_NAME + " -u \"" + user + "\" -p \""
					+ password.getPassword() + "\"";
			if (mustchange)
				args = args + " -Fx"; // Activa con cambio de contraseña
			else
				args = args + " -F"; // Activa y válida
			args = args + " -q";
			result = p.exec(args + suffix);
		} catch (Exception e) {
			throw new InternalErrorException(e.toString());
		}
	}

	private String encode(String param) {
		return "'" + param.replaceAll("'", "'\''") + "'";
	}

	public void updateUserPasswordLinux(String user, Usuari ui,
			Password password, boolean mustchange)
			throws java.rmi.RemoteException, InternalErrorException {
		TimedProcess p;
		try {
			// Comprobar si el usuario existe
			p = new TimedProcess(4000);
			p.setEnvironment(environment);
			int result = p
					.exec(new String[]{NET_NAME,"rpc","user", "get_info", user,suffix, suffix2});
			// Si el usuario no existe -> Error interno
			if (result != 0) {
				throw new InternalErrorException("Usuario no existente " + user);
			}
			LinkedList<String> args = new LinkedList<String>();
			args.add(NET_NAME);
			args.add("rpc");
			args.add("user");
			args.add("set_info");
			args.add(user);
			args.add("password="+password.getPassword());
			if (mustchange)
				args.add("flags=np"); // Activa con cambio de contraseña
			else
				args.add("flags=nP"); // Activa y válida
			args.add(suffix);
			args.add(suffix2);
			result = p.exec(args.toArray(new String[args.size()]));
		} catch (Exception e) {
			throw new InternalErrorException(e.toString());
		}
	}

	public void updateUserPassword(String user, Usuari ui, Password password,
			boolean mustchange) throws java.rmi.RemoteException,
			InternalErrorException {
		if (isWindows)
			updateUserPasswordWindows(user, ui, password, mustchange);
		else
			updateUserPasswordLinux(user, ui, password, mustchange);
	}

	/**
	 * Validar la contraseña del usuario. Utiliza el mandatao logonuser
	 */
	public boolean validateUserPasswordWindows(String user, Password password)
			throws java.rmi.RemoteException, InternalErrorException {
		TimedProcess p;
		try {
			// Comprobar si la contraseña es válida
			p = new TimedProcess(4000);
			System.out.println("validate: " + user);
			int result = p.exec(EXE_NAME + " -i \"" + user + "\" -q -S \""
					+ serverName + "\" --user \"" + serverName + "\\" + user
					+ "\" --password \"" + password.getPassword() + "\"");
			// Si el usuario no existe -> Error interno
			// Si el usuario no existe -> Error interno
			System.out.println("validate: result=" + Integer.toString(result));
			System.out.println("          message=" + p.getOutput());
			return result == 0;
		} catch (Exception e) {
			throw new InternalErrorException(e.toString());
		}
	}

	public boolean validateUserPasswordLinux(String user, Password password)
			throws java.rmi.RemoteException, InternalErrorException {
		TimedProcess p;
		try {
			// Comprobar si la contraseña es válida
			p = new TimedProcess(4000);
			p.setEnvironment(environment);
			System.out.println("validate: " + user);
			int result = p.exec(new String[] {NET_NAME,"rpc","user","get_info",user,
					"-S",serverName,"-U", user+ "%"+ password.getPassword()});
			return result == 0;
		} catch (Exception e) {
			throw new InternalErrorException(e.toString());
		}
	}

	public boolean validateUserPassword(String user, Password password)
			throws java.rmi.RemoteException, InternalErrorException {
		if (isWindows)
			return validateUserPasswordWindows(user, password);
		else
			return validateUserPasswordLinux(user, password);
	}

	public void updateUserWindows(String user, Usuari ui)
			throws RemoteException, InternalErrorException {
		try {
			// Comprobar si el usuario existe
			TimedProcess p = new TimedProcess(4000);
			int result = p.exec(EXE_NAME + " -i \"" + user + "\" -S \""
					+ serverName + "\" -q" + suffix);
			// Crear el usuario si no existe
			if (result != 0) {
				result = p.exec(EXE_NAME + " -a \"" + user + "\" -S \""
						+ serverName + "\" -Fe -q" + suffix);
				if (result != 0) {
					throw new InternalErrorException("Error creando usuario "
							+ user);
				}
			}
			// Obtener los groups del usuario
			StringBuffer groupsConcat = new StringBuffer();
			for (Grup grup : getServer().getUserGroups(user, getCodi())) {
				if (groupsConcat.length() > 0)
					groupsConcat.append(",");
				groupsConcat.append(grup.getCodi());
			}
			for (RolGrant role : getServer().getAccountRoles(user, getCodi())) {
				if (groupsConcat.length() > 0)
					groupsConcat.append(",");
				groupsConcat.append(role.getRolName());
			}
			// Modificar sus datos
			String args = EXE_NAME + " -u \"" + user + "\" -S \"" + serverName
					+ "\" -n \"" + ui.getFullName() + "\" ";
			if (ui.getServidorHome() == null
					|| ui.getServidorHome().equals("null"))
				args = args + "-H \"\" -h \"\"\"\\\\";
			else
				args = args + "-H H: -h \"\\\\" + ui.getServidorHome() + "\\"
						+ user + "\" ";

			if (ui.getServidorPerfil() == null
					|| ui.getServidorPerfil().equals("null"))
				args = args + "-P \"\"";
			else
				args = args + "-P \"\\\\" + ui.getServidorPerfil()
						+ "\\PROFILES\\" + user;

			args = args + " -g \"" + groupsConcat.toString() + "\"";
			args = args + " -q";
			result = p.exec(args + suffix);
			if (result != 0)
				throw new InternalErrorException("Error creando usuario "
						+ user);

			// Li establim una contrasenya inicial
			Password pass = getServer().getOrGenerateUserPassword(user,
					getCodi());
			if (pass != null) {
				updateUserPassword(user, ui, pass, false);
			}
		} catch (Exception e) {
			throw new InternalErrorException("Error intern", e);
		}
	}

	public void updateUserLinux(String user, Usuari ui) throws RemoteException,
			InternalErrorException {
		try {
			// Comprobar si el usuario existe
			TimedProcess p = new TimedProcess(4000);
			p.setEnvironment(environment);
			// Crear el usuario si no existe

			int result = p.exec(new String[] {NET_NAME, "rpc", "user","get_info", user, suffix, suffix2});

			LinkedList<String> args = new LinkedList<String>();
			args.add(NET_NAME);
			args.add("rpc");
			args.add("user");
			if (result != 0) {
				args.add("add");
				args.add(user);
				// Set initial password
				Password pass = getServer().getOrGenerateUserPassword(user,
						getCodi());
				if (pass != null) {
					args.add ("password="+pass.getPassword());
					args.add ("flags=nP");
				}
			} else {
				args.add("set_info");
				args.add(user);
			}
			args.add("full_name="+ui.getFullName());
			
			if (ui.getServidorHome() != null
					&& !ui.getServidorHome().equals("null"))
			{
				args.add("home_dir=\\\\"+ui.getServidorHome()+"\\"+ui.getCodi());
				args.add("home_dir_drive=H:");
			}
			else
			{
				args.add("home_dir=");
				args.add("home_dir_drive=");
			}
			if (ui.getServidorPerfil() != null
					&& !ui.getServidorPerfil().equals("null"))
			{
				args.add("profile=\\\\"+ui.getServidorPerfil()+"\\PROFILES\\"+ui.getCodi());
			}
			else
			{
				args.add("profile=");
			}
			args.add (suffix);
			args.add (suffix2);
			
			result = p.exec (args.toArray(new String[args.size()]));


			if (result != 0)
				throw new InternalErrorException("Error creando usuario "
						+ user+":\n"+p.getOutput()+"\n"+p.getError());

		} catch (Exception e) {
			throw new InternalErrorException("Error intern", e);
		}
	}

	public void updateUser(String user, Usuari ui) throws RemoteException,
			InternalErrorException {
		if (isWindows)
			updateUserWindows(user, ui);
		else
			updateUserLinux(user, ui);
	}

	public void removeUserWindows(String user) throws RemoteException,
			InternalErrorException {
		TimedProcess p = new TimedProcess(4000);
		try {
			int result = p.exec(EXE_NAME + " -i \"" + user + "\" -S \""
					+ serverName + "\" -q" + suffix);
			// Crear el usuario si no existe
			if (result != 0) {
				return;
			}
			// Modificar sus datos
			String args = EXE_NAME + " -u \"" + user + "\" -S \"" + serverName
					+ "\"  -Fd -q"; // Cuenta
			// deshabilitada
			result = p.exec(args + suffix);
			if (result != 0)
				throw new InternalErrorException(
						"Error deshabilitando usuario " + user);
		} catch (Exception e) {
			throw new InternalErrorException("Error intern", e);
		}

	}

	public void removeUserLinux(String user) throws RemoteException,
			InternalErrorException {
		TimedProcess p = new TimedProcess(4000);
		p.setEnvironment(environment);
		try {
			int result = p.exec(new String[] {NET_NAME, "rpc", "user", "get-info ", user, suffix, suffix2});
			if (result != 0) {
				return;
			}
			result = p.exec(new String [] {NET_NAME, "rpc", "user","set-info", user, "flags=d", suffix, suffix2});
			if (result != 0)
				throw new InternalErrorException(
						"Error deshabilitando usuario " + user);
		} catch (Exception e) {
			throw new InternalErrorException("Error intern", e);
		}

	}

	public void removeUser(String user) throws RemoteException,
			InternalErrorException {
		if (isWindows)
			removeUserWindows(user);
		else
			removeUserLinux(user);
	}

	public void updateUser(String user, String description)
			throws RemoteException, InternalErrorException {
		Usuari u = new Usuari();
		u.setFullName(description);
		updateUser(user, u);
	}

	public List<String> getAccountsListLinux() throws RemoteException,
			InternalErrorException {
		LinkedList<String> list = new LinkedList<String>();
		TimedProcess p = new TimedProcess(10000);
		p.setEnvironment(environment);
		int result;
		try {
			p.execNoWait(new String[] {NET_NAME, "rpc","user", suffix, suffix2});
			BufferedReader in = new BufferedReader(new InputStreamReader(
					p.getOutputStream()));
			String line = in.readLine();
			while (line != null) {
				if (line.trim().length() > 0)
					list.add(line);
				line = in.readLine();
			}
			p.consumeError();
			result = p.join();
		} catch (IOException e) {
			throw new InternalErrorException("Error when looking for accounts",
					e);
		} catch (TimedOutException e) {
			throw new InternalErrorException(
					"Timeout when looking for accounts", e);
		}

		if (result != 0) {
			throw new InternalErrorException(
					"Error when looking for accounts: " + p.getError());
		}
		return list;
	}

	public List<String> getAccountsListWindows() throws RemoteException,
			InternalErrorException {
		LinkedList<String> list = new LinkedList<String>();
		TimedProcess p = new TimedProcess(10000);
		int result;
		try {
			p.execNoWait(EXE_NAME + " --list-users -q " + suffix);
			BufferedReader in = new BufferedReader(new InputStreamReader(
					p.getOutputStream()));
			String line = in.readLine();
			while (line != null) {
				if (line.trim().length() > 0)
					list.add(line);
				line = in.readLine();
			}
			p.consumeError();
			result = p.join();
		} catch (IOException e) {
			throw new InternalErrorException("Error when looking for accounts",
					e);
		} catch (TimedOutException e) {
			throw new InternalErrorException(
					"Timeout when looking for accounts", e);
		}

		if (result != 0) {
			p.consumeError();
			throw new InternalErrorException(
					"Error when looking for accounts: " + p.getError());
		}
		return list;
	}

	public List<String> getAccountsList() throws RemoteException,
			InternalErrorException {
		if (isWindows)
			return getAccountsListWindows();
		else
			return getAccountsListLinux();
	}

	public Account getAccountInfoWindows(String userAccount)
			throws RemoteException, InternalErrorException {
		TimedProcess p = new TimedProcess(10000);
		int result;
		try {
			result = p.exec(EXE_NAME + " -i \"" + userAccount + "\" -q "
					+ suffix);

			if (result != 0) {
				p.consumeError();
				throw new InternalErrorException(
						"Error when looking for accounts: " + p.getError());
			}

			String in = p.getOutput();
			String tags[] = in.split(":");
			Account acc = new Account();
			acc.setName(tags[0]);
			if (tags[2].trim().length() == 0)
				acc.setDescription("- no description -");
			else
				acc.setDescription(tags[2]);
			try {
				int seconds = Integer.decode(tags[13]).intValue();
				Calendar c = Calendar.getInstance();
				c.add(-seconds, Calendar.SECOND);
				acc.setLastPasswordSet(c);
			} catch (Exception e) {
			}
			try {
				int flags = Integer.decode(tags[12]).intValue();
				acc.setDisabled((flags & 2) == 2);
			} catch (Exception e) {
			}
			return acc;
		} catch (IOException e) {
			throw new InternalErrorException("Error when looking for accounts",
					e);
		} catch (TimedOutException e) {
			throw new InternalErrorException(
					"Timeout when looking for accounts", e);
		}
	}

	public Account getAccountInfoLinux(String userAccount)
			throws RemoteException, InternalErrorException {
		TimedProcess p = new TimedProcess(10000);
		p.setEnvironment(environment);
		int result;
		try {
			result = p.exec(new String [] {NET_NAME, "rpc", "user","get_info",userAccount, suffix, suffix2});

			if (result != 0) {
				p.consumeError();
				throw new InternalErrorException(
						"Error when looking for accounts: " + p.getError());
			}

			String in = p.getOutput();
			String lines[] = in.split("\n");
			Account acc = new Account();
			for (String line : in.split("\n")) {
				if (line.startsWith("full_name: "))
					acc.setDescription(line.substring(10));
				if (line.startsWith("comment: ") && 
						(acc.getDescription() == null || acc.getDescription().trim().length() == 0))
					acc.setDescription(line.substring(9));
				if (line.startsWith("name: "))
					acc.setName(line.substring(6));
				if (line.startsWith("password_age: ")) {
					long i = Long.decode(line.substring(14));
					acc.setLastPasswordSet(Calendar.getInstance());
					acc.getLastPasswordSet().setTime(
							new Date(System.currentTimeMillis() - i * 1000));
				}
			}
			if (acc.getDescription() == null || acc.getDescription().trim().length() == 0)
				acc.setDescription(userAccount+" account");
			return acc;
		} catch (IOException e) {
			throw new InternalErrorException("Error when looking for accounts",
					e);
		} catch (TimedOutException e) {
			throw new InternalErrorException(
					"Timeout when looking for accounts", e);
		}
	}

	public Account getAccountInfo(String userAccount) throws RemoteException,
			InternalErrorException {
		if (isWindows)
			return getAccountInfoWindows(userAccount);
		else
			return getAccountInfoLinux(userAccount);
	}

	public List<String> getRolesListWindows() throws RemoteException,
			InternalErrorException {
		LinkedList<String> list = new LinkedList<String>();
		TimedProcess p = new TimedProcess(10000);
		int result;
		try {
			p.execNoWait(EXE_NAME + " --list-groups -q " + suffix);
			BufferedReader in = new BufferedReader(new InputStreamReader(
					p.getOutputStream()));
			String line = in.readLine();
			while (line != null) {
				if (line.trim().length() > 0)
					list.add(line);
				line = in.readLine();
			}
			p.consumeError();
			result = p.join();
		} catch (IOException e) {
			throw new InternalErrorException("Error when looking for accounts",
					e);
		} catch (TimedOutException e) {
			throw new InternalErrorException(
					"Timeout when looking for accounts", e);
		}

		if (result != 0) {
			p.consumeError();
			throw new InternalErrorException(
					"Error when looking for accounts: " + p.getError());
		}
		return list;
	}

	public List<String> getRolesListLinux(String type) throws RemoteException,
			InternalErrorException {
		LinkedList<String> list = new LinkedList<String>();
		TimedProcess p = new TimedProcess(10000);
		p.setEnvironment(environment);
		int result;
		try {
			p.execNoWait(new String [] {NET_NAME, "rpc", "group", "list", type, "-L", suffix, suffix2});
			BufferedReader in = new BufferedReader(new InputStreamReader(
					p.getOutputStream()));
			String line = in.readLine();
			while (line != null) {
				if (line.trim().length() > 0)
					list.add(line);
				line = in.readLine();
			}
			p.consumeError();
			result = p.join();
		} catch (IOException e) {
			throw new InternalErrorException("Error when looking for accounts",
					e);
		} catch (TimedOutException e) {
			throw new InternalErrorException(
					"Timeout when looking for accounts", e);
		}

		if (result != 0) {
			p.consumeError();
			throw new InternalErrorException(
					"Error when looking for accounts: " + p.getError());
		}
		return list;
	}

	public List<String> getRolesListLinux() throws RemoteException,
		InternalErrorException {
		LinkedList<String> list = new LinkedList<String>();
		list.addAll ( getRolesListLinux("local") );
		list.addAll ( getRolesListLinux("builtin") );
		return list;
	}
	public List<String> getRolesList() throws RemoteException,
			InternalErrorException {
		if (isWindows)
			return getRolesListWindows();
		else
			return getRolesListLinux();
	}

	public Rol getRoleFullInfoWindows(String roleName) throws RemoteException,
			InternalErrorException {
		TimedProcess p = new TimedProcess(10000);
		int result;
		try {
			result = p.exec(EXE_NAME + " --group-info \"" + roleName + "\" -q "
					+ suffix);

			if (result != 0) {
				p.consumeError();
				throw new InternalErrorException(
						"Error when looking for accounts: " + p.getError());
			}

			String in = p.getOutput();
			String tags[] = in.split(":");
			Rol r = new Rol();
			r.setNom(roleName);
			r.setDescripcio(tags[1]);
			return r;
		} catch (IOException e) {
			throw new InternalErrorException("Error when looking for accounts",
					e);
		} catch (TimedOutException e) {
			throw new InternalErrorException(
					"Timeout when looking for accounts", e);
		}
	}

	public Rol getRoleFullInfoLinux(String roleName) throws RemoteException,
			InternalErrorException {
		Rol r = new Rol();
		r.setNom(roleName);
		r.setDescripcio(roleName+" local group");
		return r;
	}

	public Rol getRoleFullInfo(String roleName) throws RemoteException,
			InternalErrorException {
		if (isWindows)
			return getRoleFullInfoWindows(roleName);
		else
			return getRoleFullInfoLinux(roleName);
	}

	public List<RolGrant> getAccountGrantsWindows(String userAccount)
			throws RemoteException, InternalErrorException {
		TimedProcess p = new TimedProcess(10000);
		int result;
		try {
			result = p.exec(EXE_NAME + " -i \"" + userAccount + "\" -q"
					+ suffix);

			if (result != 0) {
				p.consumeError();
				throw new InternalErrorException(
						"Error when looking for accounts: " + p.getError());
			}

			String in = p.getOutput();
			String tags[] = in.split(":");
			String localGroups[] = tags[10].split(",");
			LinkedList<RolGrant> rolGrants = new LinkedList<RolGrant>();

			for (String localGroup : localGroups) {
				if (localGroup.trim().length() > 0) {
					RolGrant rg = new RolGrant();
					rg.setRolName(localGroup);
					rg.setDispatcher(getCodi());
					rg.setOwnerAccountName(userAccount);
					rg.setOwnerDispatcher(getCodi());
					rolGrants.add(rg);
				}
			}
			return rolGrants;
		} catch (IOException e) {
			throw new InternalErrorException("Error when looking for accounts",
					e);
		} catch (TimedOutException e) {
			throw new InternalErrorException(
					"Timeout when looking for accounts", e);
		}
	}

	public List<RolGrant> getAccountGrantsLinux(String userAccount)
			throws RemoteException, InternalErrorException {
		TimedProcess p = new TimedProcess(10000);
		p.setEnvironment(environment);
		int result;
		try {
			String match = nbServerName+"\\"+userAccount;
			LinkedList<RolGrant> rolGrants = new LinkedList<RolGrant>();
			for (String roleName : getRolesList())
			{
				result = p.exec(new String[]{NET_NAME, "rpc", "group","members",roleName,"-L",suffix, suffix2});
				String in = p.getOutput();
				for (String user: in.split("\n"))
				{
					if (match.equals(user))
					{
						RolGrant rg = new RolGrant();
						rg.setRolName(roleName);
						rg.setDispatcher(getCodi());
						rg.setOwnerAccountName(userAccount);
						rg.setOwnerDispatcher(getCodi());
						rolGrants.add(rg);
						break;
					}
				}
				if (result != 0) {
					throw new InternalErrorException(
							"Error when looking for accounts: " + p.getError());
				}
			}
			return rolGrants;
		} catch (IOException e) {
			throw new InternalErrorException("Error when looking for accounts",
					e);
		} catch (TimedOutException e) {
			throw new InternalErrorException(
					"Timeout when looking for accounts", e);
		}
	}

	public List<RolGrant> getAccountGrants(String userAccount)
			throws RemoteException, InternalErrorException {
		if (isWindows)
			return getAccountGrantsWindows(userAccount);
		else
			return getAccountGrantsLinux(userAccount);
	}

	public void updateRole(Rol rol) throws RemoteException,
			InternalErrorException {
		if (! isWindows )
		{
			try {
				String roleName = rol.getNom();
				TimedProcess p = new TimedProcess(10000);
				p.setEnvironment(environment);
				int result;
				if ( ! getRolesList().contains(roleName))
				{
					result = p.exec(new String[] {NET_NAME,"rpc",
							"group","add",roleName,"-C",rol.getDescripcio(),"-L",suffix,suffix2});
					if (result != 0) {
						throw new InternalErrorException(
								"Error creating a local group: " + p.getError());
					}
				}
				Collection<Account> accounts = getServer().getRoleActiveAccounts(rol.getId(), getCodi());
				Collection<String> currentAccounts = getCurrentAccountsLinux (roleName);
				
				// Add new members
				for (Iterator<Account> it = accounts.iterator(); it.hasNext();)
				{
					Account acc = it.next();
					if (currentAccounts.contains(acc.getName()))
						currentAccounts.remove(acc.getName());
					else if (! acc.isDisabled() && acc.getType() != AccountType.IGNORED)
					{
						result = p.exec (new String[] {NET_NAME,"rpc",
								"group","addmem",roleName,acc.getName(),"-L",suffix,suffix2});
						if (result != 0) {
							throw new InternalErrorException(
									"Error when adding an account to a local grouop: " + p.getError());
						}
					}
				}
				// Remove old members
				for (String member: currentAccounts)
				{
					result = p.exec (new String [] {NET_NAME, "rpc",
							"group","delmem",roleName,member,"-L",suffix,suffix2});
					if (result != 0) {
						throw new InternalErrorException(
								"Error when adding an account to a local grouop: " + p.getError());
					}
				}
				
			} catch (IOException e) {
				throw new InternalErrorException("Error when looking for accounts",
						e);
			} catch (TimedOutException e) {
				throw new InternalErrorException(
						"Timeout when looking for accounts", e);
			} catch (UnknownRoleException e) {
				// Nothing to do. Ignore exception
			}
		}
	}

	private Collection<String> getCurrentAccountsLinux(String roleName) throws InternalErrorException {
		TimedProcess p = new TimedProcess(10000);
		p.setEnvironment(environment);
		int result;
		try {
			LinkedList<String> list = new LinkedList<String>();
			String match = nbServerName+"\\";
			result = p.exec(new String[] {NET_NAME, "rpc","group","members",roleName,"-L",suffix, suffix2});
			String in = p.getOutput();
			for (String user: in.split("\n"))
			{
				if (user.startsWith(match))
				{
					list.add (user.substring(match.length()));
				}
			}
			if (result != 0) {
				throw new InternalErrorException(
						"Error when looking for accounts: " + p.getError());
			}
			return list;
		} catch (IOException e) {
			throw new InternalErrorException("Error when looking for accounts",
					e);
		} catch (TimedOutException e) {
			throw new InternalErrorException(
					"Timeout when looking for accounts", e);
		}
	}

	public void removeRole(String roleName, String dispatcher)
			throws RemoteException, InternalErrorException {
		if (! isWindows )
		{
			try {
				TimedProcess p = new TimedProcess(10000);
				p.setEnvironment(environment);
				int result;
				if ( getRolesList().contains(roleName))
				{
					result = p.exec(new String[] {NET_NAME, "rpc","group","delete",roleName,"-L",suffix,suffix2});
					if (result != 0) {
						throw new InternalErrorException(
								"Error when deleting a local group: " + p.getError());
					}
				}
				
			} catch (IOException e) {
				throw new InternalErrorException("Error when looking for accounts",
						e);
			} catch (TimedOutException e) {
				throw new InternalErrorException(
						"Timeout when looking for accounts", e);
			}
		}

	}

	public void getNbServerName()
			throws RemoteException, InternalErrorException {
		TimedProcess p = new TimedProcess(10000);
		p.setEnvironment(environment);
		int result;
		try {
			result = p.exec(new String [] {NET_NAME, "rpc", "info", suffix, suffix2});

			if (result != 0) {
				p.consumeError();
				throw new InternalErrorException(
						"Error when looking for accounts: " + p.getError());
			}

			String in = p.getOutput();
			String lines[] = in.split("\n");
			Account acc = new Account();
			for (String line : in.split("\n")) {
				if (line.startsWith("Domain Name: "))
					nbServerName = line.substring (13).trim();
			}
			if (nbServerName == null || nbServerName.length() == 0)
				throw new InternalErrorException ("Unable to get netbios server name");
		} catch (IOException e) {
			throw new InternalErrorException("Error when looking for accounts",
					e);
		} catch (TimedOutException e) {
			throw new InternalErrorException(
					"Timeout when looking for accounts", e);
		}
	}

}
