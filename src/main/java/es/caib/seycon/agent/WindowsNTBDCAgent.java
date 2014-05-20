// Copyright (c) 2000 Govern  de les Illes Balears
// $Log: WindowsNTBDCAgent.java,v $
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
// Revision 1.6  2011-03-15 11:10:05  u07286
// Afegida informacío de depuració
//
// Revision 1.5  2010-03-15 10:23:31  u07286
// Movido a tag HEAD
//
// Revision 1.2.2.2  2009-06-16 11:23:01  u07286
// Merge a seycon-3.0.15
//
// Revision 1.2.2.1  2009-03-26 13:00:09  u89559
// *** empty log message ***
//
// Revision 1.2  2008-06-12 08:02:51  u07286
// Backport agost 2008
//
// Revision 1.5  2007-08-13 12:19:32  u07286
// [T225] Eliminada información de DEBUG
//
// Revision 1.4  2005-08-10 08:37:14  u07286
// Cambiado mecanismo de confianza en el servidor
//
// Revision 1.3  2004/03/15 12:08:09  u07286
// Conversion UTF-8
//
// Revision 1.2  2004/03/15 11:57:53  u07286
// Agregada documentacion JavaDoc
//

package es.caib.seycon.agent;

import java.rmi.RemoteException;

import es.caib.seycon.*;

import es.caib.seycon.ng.comu.Password;
import es.caib.seycon.ng.comu.Usuari;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownUserException;
import es.caib.seycon.ng.sync.intf.UserMgr;
import es.caib.seycon.util.TimedProcess;

/**
 * Gestión de backup domain controlers. Inicialmente desarrollado para Windows
 * NT 4.0
 * <P>
 * 
 * @author $Author: u07286 $
 * @version $Revision: 1.3 $
 */

public class WindowsNTBDCAgent extends WindowsNTAgent implements UserMgr {

    /**
     * Constructor
     */
    public WindowsNTBDCAgent() throws java.rmi.RemoteException {
        System.out.println("Iniciado Agente Windows NT Backup Domain Controller");
    }

    /**
     * Se valida la contraseña del usuario. Se realiza mediante la ejecución del
     * programa logonuser, el cual intenta hacer una Impersonation
     */
    public boolean validateUserPassword(String user, Password password) throws RemoteException, InternalErrorException {
        log.info("Validating password for {} {}", user, password);
        TimedProcess p;
        if (user.toLowerCase().equals("administrator"))
            return false;
        try {
            // Comprobar si la contraseña es válida
            p = new TimedProcess(4000);
            int result = p.exec("logonuser \"" + user + "\" . \"" + password.getPassword() + "\"");
            // Si el usuario no existe -> Error interno
            if (result == 2) {
                String warning = "Error: El usuario debe cambiar su contraseña antes de iniciar la sesión por primera vez.";
                String message = p.getOutput();
                log.info("Ejecutado logonuser {} - Result {}", user, message);
                if (message.length() >= warning.length()
                        && message.substring(0, warning.length()).equalsIgnoreCase(warning)) {
                    log.info("Password validada", null, null);
                    return true;
                } else if (message.contains("must be changed before logging")) {
                    log.info("Password validada", null, null);
                    return true;
                } else {
                    log.info("Password rechazada", null, null);
                    return false;
                }
            } else {
                log.info("Validate user {}", user, null);
                log.info("Result = ({}): {}", new Integer(result), p.getOutput());
                return result == 0;
            }
        } catch (Exception e) {
            throw new InternalErrorException(e.toString());
        }
    }

    public void updateUser(String userName, Usuari userData) throws RemoteException,
            InternalErrorException {
    }

    public void removeUser(String userName) throws RemoteException, InternalErrorException {
    }

    public void updateUserPassword(String userName, Usuari userData, Password password,
            boolean mustchange) throws RemoteException, InternalErrorException {
    }


    public String createUserKey(Usuari userData) throws RemoteException, InternalErrorException {
        return null;
    }

	public void updateUser(String accountName, String description)
			throws RemoteException, InternalErrorException {
	}
}
