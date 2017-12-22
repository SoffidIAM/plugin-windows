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

package es.caib.seycon.agent;

import java.rmi.RemoteException;

import es.caib.seycon.*;
import es.caib.seycon.ng.comu.Grup;
import es.caib.seycon.ng.comu.Password;
import es.caib.seycon.ng.comu.RolGrant;
import es.caib.seycon.ng.comu.Usuari;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.sync.intf.UserMgr;
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
public class WindowsNTWAgent extends WindowsNTAgent implements UserMgr {

    /**
     * Constructor
     */
    public WindowsNTWAgent() throws java.rmi.RemoteException {
        System.out.println("Iniciado Agente Windows NT Primary Domain Controller");
    }

    /**
     * Actualizar la contraseña del usuario
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

    public void updateUser(String user, Usuari ui) throws RemoteException,
            InternalErrorException {
        try {
            // Comprobar si el usuario existe
            TimedProcess p = new TimedProcess(4000);
            int result = p.exec("usradm -i " + user + " -q");
            // Crear el usuario si no existe
            if (result != 0) {
            	Password pass = getServer().getAccountPassword(user, getDispatcher().getCodi());
            	result = p.exec("usradm -a \"" + user + "\" -Fe -q -p \"" + pass.getPassword() + "\"");
                if (result != 0) {
                    throw new InternalErrorException("Error creando usuario " + user);
                }
            }
            // Obtener los groups del usuario
            StringBuffer groupsConcat = new StringBuffer();
            for (Grup grup: getServer().getUserGroups(user, getCodi())) {
                if (groupsConcat.length() > 0)
                    groupsConcat.append(",");
                groupsConcat.append (grup.getCodi());
            }
            for (RolGrant role: getServer().getAccountRoles(user, getCodi())) {
                if (groupsConcat.length() > 0)
                    groupsConcat.append(",");
                groupsConcat.append (role.getRolName());
            }
            // Modificar sus datos
            String args = "usradm -u \"" + user + "\" -n \"" + ui.getNom() + " " + ui.getPrimerLlinatge();
            if (ui.getSegonLlinatge() != null)
                args = args + " " + ui.getSegonLlinatge();
            args = args + "\" -H H: -h \"\\\\" + ui.getServidorHome() + "\\" + user + "\" -P \"\\\\"
                    + ui.getServidorPerfil() + "\\PROFILES\\" + user;
            args = args + " -b";
            // else args = args + " -Fe";
            args = args + " -q";
            result = p.exec(args);
            if (result != 0)
                throw new InternalErrorException("Error creando usuario " + user);
    
            // Li establim una contrasenya inicial
            Password pass = getServer().getOrGenerateUserPassword(user, getCodi());
            if (pass != null) {
                updateUserPassword(user, ui, pass, false);
            }
        } catch (Exception e) {
            throw new InternalErrorException("Error intern", e);
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

	public void updateUser(String user, String description)
			throws RemoteException, InternalErrorException {
        try {
            // Comprobar si el usuario existe
            TimedProcess p = new TimedProcess(4000);
            int result = p.exec("usradm -i " + user + " -q");
            // Crear el usuario si no existe
            if (result != 0) {
            	Password pass = getServer().getOrGenerateUserPassword(user, getDispatcher().getCodi());
            	String args = "usradm -a \"" + user + "\" -Fe -q -p \"" + pass.getPassword() + "\"";
                log.info("Executing :"+args);
				result = p.exec(args);
                if (result != 0) {
                    throw new InternalErrorException("Error creando usuario " + user);
                }
            }
            // Obtener los groups del usuario
            StringBuffer groupsConcat = new StringBuffer();
            for (Grup grup: getServer().getUserGroups(user, getCodi())) {
                if (groupsConcat.length() > 0)
                    groupsConcat.append(",");
                groupsConcat.append (grup.getCodi());
            }
            for (RolGrant role: getServer().getAccountRoles(user, getCodi())) {
                if (groupsConcat.length() > 0)
                    groupsConcat.append(",");
                groupsConcat.append (role.getRolName());
            }
            // Modificar sus datos
            String args = "usradm -u \"" + user + "\" -n \"" + description;
            args = args + "\"";
            // args = args + " -b";
            args = args + " -Fe";
            args = args + " -q";
            log.info("Executing :"+args);
            result = p.exec(args);
            if (result != 0)
                throw new InternalErrorException("Error creando usuario " + user);
    
            // Li establim una contrasenya inicial
            Password pass = getServer().getOrGenerateUserPassword(user, getCodi());
            if (pass != null) {
                updateUserPassword(user, null, pass, false);
            }
        } catch (Exception e) {
            throw new InternalErrorException("Error intern", e);
        }
	}
}
