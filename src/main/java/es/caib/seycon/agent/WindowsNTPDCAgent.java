// Copyright (c) 2000 Govern  de les Illes Balears
// $Log: WindowsNTPDCAgent.java,v $
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
// Revision 1.24  2010-03-15 10:23:31  u07286
// Movido a tag HEAD
//
// Revision 1.2.2.2  2009-04-28 12:10:50  u89559
// *** empty log message ***
//
// Revision 1.23  2009-04-28 02:45:59  u07286
// el PDC no debe cargar javadisk
//
// Revision 1.22  2009-03-09 12:06:50  u89559
// *** empty log message ***
//
// Revision 1.21  2009-03-09 11:03:00  u89559
// *** empty log message ***
//
// Revision 1.20  2009-03-09 10:22:21  u89559
// *** empty log message ***
//
// Revision 1.19  2009-03-06 13:31:01  u89559
// *** empty log message ***
//
// Revision 1.18  2009-03-06 13:23:36  u89559
// *** empty log message ***
//
// Revision 1.17  2009-03-04 11:53:33  u89559
// *** empty log message ***
//
// Revision 1.16  2009-02-27 11:34:12  u89559
// *** empty log message ***
//
// Revision 1.15  2009-02-25 12:50:22  u86957
// M�s informaci� a logon fallido
//
// Revision 1.14  2009-02-25 12:35:35  u86957
// Mas informacion relativa a logon fallido
//
// Revision 1.13  2009-02-25 07:57:34  u89559
// *** empty log message ***
//
// Revision 1.12  2009-02-24 13:23:50  u89559
// *** empty log message ***
//
// Revision 1.11  2009-02-24 08:33:14  u89559
// *** empty log message ***
//
// Revision 1.7  2009-02-24 08:19:58  u89559
// *** empty log message ***
//
// Revision 1.6  2009-02-20 11:37:55  u89559
// *** empty log message ***
//
// Revision 1.5  2009-02-20 10:24:51  u89559
// *** empty log message ***
//
// Revision 1.4  2009-02-20 10:07:59  u89559
// *** empty log message ***
//
// Revision 1.3  2009-02-17 12:45:44  u89559
// *** empty log message ***
//
// Revision 1.2  2008-11-05 12:33:15  u89559
// *** empty log message ***
//
// Revision 1.1  2007-09-06 12:51:10  u89559
// [T252]
//
// Revision 1.7  2005-08-10 08:37:14  u07286
// Cambiado mecanismo de confianza en el servidor
//
// Revision 1.6  2004/03/15 12:08:09  u07286
// Conversion UTF-8
//
// Revision 1.5  2004/03/15 11:57:54  u07286
// Agregada documentacion JavaDoc
//

package es.caib.seycon.agent;

import java.rmi.RemoteException;

import es.caib.seycon.ng.comu.Grup;
import es.caib.seycon.ng.comu.Maquina;
import es.caib.seycon.ng.comu.Password;
import es.caib.seycon.ng.comu.RolGrant;
import es.caib.seycon.ng.comu.Usuari;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.sync.intf.HostMgr;
import es.caib.seycon.ng.sync.intf.UserMgr;
import es.caib.seycon.util.TimedProcess;

/**
 * Gestión de Windows NT Primary Domain Controller
 * <P>
 * 
 * @author $Author: u07286 $
 * @version $Revision: 1.3 $
 */

public class WindowsNTPDCAgent extends WindowsNTAgent implements UserMgr, HostMgr {

    @Override
    public void init() throws InternalErrorException {
    	super.init();
    }

    /**
     * Constructor. No usa ningún parámetro especial
     */
    public WindowsNTPDCAgent() throws java.rmi.RemoteException {
        log.info("Iniciado Agente Windows NT Primary Domain Controller");
    }

    // static char contadorHashPass = 'a';

    /**
     * Actualiza el usuario en el dominio. Utiliza el programa usradm más
     * versatil que los mandatos net user
     */
    public void updateUser(String user, Usuari ui) throws java.rmi.RemoteException,
            InternalErrorException {
        user = user.trim();
        int result;
        TimedProcess p;
        // if (user.toLowerCase().equals ("administrator")) return;
        // if (user.toLowerCase().equals ("administrador")) return;
        try {
            // Comprobar si el usuario existe
            p = new TimedProcess(4000);
            result = p.exec("usradm -i " + user + " -q");
            // Crear el usuario si no existe
            if (result != 0) {
                Password passwd = getServer().getAccountPassword(user, getCodi());
                String pass = passwd.getPassword();

                result = p.exec("usradm -a \"" + user + "\" -Fe -q");
                if (result != 0) {
                    throw new InternalErrorException("Error creando usuario " + user);
                }
                result = p.exec("usradm -u \"" + user + "\" -p \"" + pass + "\" -Fe -q ");
                if (result != 0) {
                    throw new InternalErrorException("Error asignando contrase?a " + p.getError());
                }
                // if (contadorHashPass == 'z') contadorHashPass = 'a';
                // else contadorHashPass = (char) ( 1 + (int) contadorHashPass);
            }
            // Obtener los groups del usuario
            StringBuffer groupsConcat = new StringBuffer("Domain Users");
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
            String args = "usradm -u \"" + user + "\" -n \"" + ui.getNom() + " "
                    + ui.getPrimerLlinatge();
            if (ui.getSegonLlinatge() != null)
                args = args + " " + ui.getSegonLlinatge();
            // Variables temporales
            String profileDir, homeDrive, homePath;
            // Perfiles
            if (ui.getServidorPerfil().equals("nul"))
                profileDir = "";
            else
                profileDir = "\\\\" + ui.getServidorPerfil() + "\\PROFILES\\" + user;
            // Homes
            if (ui.getServidorHome().equals("nul")) {
                homeDrive = "";
                homePath = "";
            } else {
                homeDrive = "H:";
                homePath = "\\\\" + ui.getServidorHome() + "\\" + user;
            }
            args = args + "\" -H \"" + homeDrive + "\" -h \"" + homePath + "\" -P \"" + profileDir
                    + "\" -f \"" + ui.getCodiGrupPrimari() + "\" -G \"" + groupsConcat.toString() + "\" ";
            args = args + " -b";
            // else args = args + " -Fe";
            args = args + " -q";
            result = p.exec(args);
            if (result != 0)
                throw new InternalErrorException("Error creando usuario " + user);
        } catch (Exception e) {
            // e.printStackTrace (System.err);
            throw new InternalErrorException(e.toString());
        }
    }

    public void removeUser(String user) throws RemoteException, InternalErrorException {
        TimedProcess p = new TimedProcess(4000);
        try {
            int result = p.exec("usradm -i " + user + " -q");
            // Crear el usuario si no existe
            if (result != 0) {
                return ;
            }
            // Modificar sus datos
            String args = "usradm -u \"" + user + "\"  -Fd -q"; // Cuenta deshabilitada
            result = p.exec(args);
            if (result != 0)
                throw new InternalErrorException("Error deshabilitando usuario " + user);
        } catch (Exception e) {
            throw new InternalErrorException("Error intern", e);
        }
    
    }

    /**
     * Utiliza el comando usradm para cambiar la contraseña del usuario
     * 
     */
    public void updateUserPassword(String user, Usuari ui, Password password, boolean mustchange)
            throws java.rmi.RemoteException, InternalErrorException {
        TimedProcess p;
        if (user.toLowerCase().equals("administrator"))
            return;
        if (user.toLowerCase().equals("administrador"))
            return;
        try {
            // Comprobar si el usuario existe
            p = new TimedProcess(4000);
            int result = p.exec("usradm -i " + user + " -q");
            // Si el usuario no existe -> Error interno
            if (result != 0) {
                throw new InternalErrorException("Usuario no existente " + user);
            }
            String args = "usradm -u \"" + user + "\" -p \"" + password.getPassword() + "\"";
            if (mustchange)
                args = args + " -Fx"; // Activa con cambio de contraseña
            else
                args = args + " -F"; // Activa y válida
            args = args + " -q";
            result = p.exec(args);
        } catch (Exception e) {
            throw new InternalErrorException(e.toString());
        }
    }
    /**
     * Validar la contraseña del usuario. Utiliza el mandatao logonuser
     */
    public boolean validateUserPassword(String user, Password password)
            throws java.rmi.RemoteException, InternalErrorException {
        TimedProcess p;
        if (user.toLowerCase().equals("administrator"))
            return false;
        if (user.toLowerCase().equals("administrador"))
            return false;
        try {
            // Comprobar si la contraseña es válida
            p = new TimedProcess(4000);
            System.out.println("validate: " + user);
            int result = p.exec("logonuser \"" + user + "\" . \"" + password.getPassword() + "\"");
            // Si el usuario no existe -> Error interno
            // Si el usuario no existe -> Error interno
            System.out.println("validate: result=" + Integer.toString(result));
            System.out.println("          message=" + p.getOutput());
            if (result == 2) {
                String warning = "Error: El usuario debe cambiar su contraseña antes de iniciar la sesión por primera vez.";
                String message = p.getOutput();
                if (message.length() >= warning.length()
                        && message.substring(0, warning.length()).equalsIgnoreCase(warning)) {
                    return true;
                } else
                    return false;
            } else
                return result == 0;
        } catch (Exception e) {
            throw new InternalErrorException(e.toString());
        }
    }


    /**
     * Ejecuta net computer para agregar o eliminar máquinas del dominio. Sólo
     * se agregan las máquinas con sistema operativo NTW (Windows NT
     * Workstation), WTS (Windows Terminal Server) y NTS (Windows NT Server)
     */
    public void updateHost(Maquina hi) throws java.rmi.RemoteException, InternalErrorException {
        String host = hi.getNom().trim();
        if (host.contains(" ")) {
            return;
        }
        System.out.println("Update host " + host);
        // Obtener los datos del host
        if (hi.getAdreca() == null || hi.getAdreca().length() == 0)
            hi = null;
        boolean delete = false;
        boolean add = false;
        if (hi == null)
            delete = true;
        else if (hi.getSistemaOperatiu().equals("NTS") || hi.getSistemaOperatiu().equals("WTS")
                || hi.getSistemaOperatiu().equals("NTW"))
            add = true;
        else
            delete = true;
        if (add) {
            System.out.println("Agregando al dominio ..");
            TimedProcess p;
            p = new TimedProcess(4000);
            try {
                int result = p.exec(new String[] { "net", "computer", "\\\\" + host.trim(),
                        "/ADD" });
                if (result != 0 && p.getError().indexOf("3782") < 0)
                    throw new InternalErrorException("Error añadiendo máquina " + host + " "
                            + p.getError());
            } catch (Exception e) {
                throw new InternalErrorException(e.toString());
            }
        }
        if (delete) {
        }
    }

    public void removeHost(String name) throws RemoteException, InternalErrorException {
        TimedProcess p;
        p = new TimedProcess(4000);
        try {
            int result = p
                    .exec(new String[] { "net", "computer", "\\\\" + name.trim(), "/DEL" });
            if (result != 0 && p.getError().indexOf("3781") < 0) {
                String error = p.getError();
                error = error.replace("\n", "");
                error = error.replace("\t", "");
                error = error.trim();
                error = error.toUpperCase();
                if (!error.contains("THERE IS NO SUCH COMPUTER")) {
                    throw new InternalErrorException("Error eliminando máquina " + name
                            + "\n Comando:  net computer \\\\" + name.trim() + " /DEL \n"
                            + p.getError());
                }
            }
        } catch (Exception e) {
            throw new InternalErrorException(e.toString());
        }
    }

    public String createUserKey(Usuari userData) throws RemoteException, InternalErrorException {
        return null;
    }

	public void updateUser(String user, String description)
			throws RemoteException, InternalErrorException {
        user = user.trim();
        int result;
        TimedProcess p;
        // if (user.toLowerCase().equals ("administrator")) return;
        // if (user.toLowerCase().equals ("administrador")) return;
        try {
            // Comprobar si el usuario existe
            p = new TimedProcess(4000);
            result = p.exec("usradm -i " + user + " -q");
            // Crear el usuario si no existe
            if (result != 0) {
                Password passwd = getServer().getAccountPassword(user, getCodi());
                String pass = passwd.getPassword();

                result = p.exec("usradm -a \"" + user + "\" -Fe -q");
                if (result != 0) {
                    throw new InternalErrorException("Error creando usuario " + user);
                }
                result = p.exec("usradm -u \"" + user + "\" -p \"" + pass + "\" -Fe -q ");
                if (result != 0) {
                    throw new InternalErrorException("Error asignando contrase?a " + p.getError());
                }
                // if (contadorHashPass == 'z') contadorHashPass = 'a';
                // else contadorHashPass = (char) ( 1 + (int) contadorHashPass);
            }
            // Obtener los groups del usuario
            StringBuffer groupsConcat = new StringBuffer("Domain Users");
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
            String args = "usradm -u \"" + user + "\" -n \"" + description;
            // Variables temporales
            String profileDir, homeDrive, homePath;
            // Perfiles
            profileDir = "";
            // Homes
            homeDrive = "";
            homePath = "";
            args = args + "\" -H \"" + homeDrive + "\" -h \"" + homePath + "\" -P \"" + profileDir
                    + "\" -G \"" + groupsConcat.toString() + "\" ";
            args = args + " -b";
            // else args = args + " -Fe";
            args = args + " -q";
            result = p.exec(args);
            if (result != 0)
                throw new InternalErrorException("Error creando usuario " + user);
        } catch (Exception e) {
            // e.printStackTrace (System.err);
            throw new InternalErrorException(e.toString());
        }
	}

}
