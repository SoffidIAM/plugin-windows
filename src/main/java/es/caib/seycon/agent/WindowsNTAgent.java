// Copyright (c) 2000 Govern  de les Illes Balears
// $Log: WindowsNTAgent.java,v $
// Revision 1.3  2012-11-05 07:42:41  u07286
// Nova versió interfície
//
// Revision 1.2  2012-06-13 13:05:31  u88683
// - Nous usuaris: propaguem la contrasenya (ActiveDirectori, WindowsNTPDCAgent, WindowsNTWAgent)
// - Ho fem compatible amb seycon-base-4.0.4 (nous paquets)
//
// Revision 1.1  2012-02-14 07:03:16  u07286
// Versió inicial
//
// Revision 1.9  2011-12-28 10:35:33  u88683
// - canviem el log.debug per log.info en certs casos (m�s informaci�)
// - s'elimina l'�s del comandament setquota [RTIR #28628] - segons sistemes ja no s'empra aquest comandament, sin� el sealloc [s'emprava si fallava el primer]
//
// Revision 1.8  2011-01-25 11:02:30  u88683
// Fem us del log.info/debug/warn enlloc del system.out/error
//
// Revision 1.8 2011-01-25 11:58:23 u88683
// canviem els system.out a log.info i log.debug
//
// Revision 1.7  2010-04-09 07:35:26  u88683
// Arreglada incidencia windows 2003 con el net share. En la pol�tica de 2003, por defecto se asigna a Everyone en el share el permiso  de s�lo lectura. Se establece acceso total al net share para Everyone. Los permisos son los que restringen el acceso
//
// Revision 1.6  2010-03-15 10:23:31  u07286
// Movido a tag HEAD
//
// Revision 1.2.2.2  2009-06-16 11:23:01  u07286
// Merge a seycon-3.0.15
//
// Revision 1.2.2.1  2009-04-28 12:10:50  u89559
// *** empty log message ***
//
// Revision 1.3  2009-04-28 02:45:53  u07286
// el PDC no debe cargar javadisk
//
// Revision 1.2  2008-06-12 08:02:51  u07286
// Backport agost 2008
//
// Revision 1.5  2007-08-13 12:16:34  u07286
// [T225] Mejorar los errores de inicializacion del javadisk
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

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.text.SimpleDateFormat;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedList;
import java.util.Vector;

import es.caib.seycon.ng.comu.Grup;
import es.caib.seycon.ng.comu.Usuari;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownGroupException;
import es.caib.seycon.ng.exception.UnknownUserException;
import es.caib.seycon.ng.sync.agent.Agent;
import es.caib.seycon.ng.sync.intf.AccessLogMgr;
import es.caib.seycon.ng.sync.intf.LogEntry;
import es.caib.seycon.ng.sync.intf.SharedFolderMgr;
import es.caib.seycon.util.TimedOutException;
import es.caib.seycon.util.TimedProcess;

/**
 * Agente para la gestion de servidores Windows NT y secuelas
 * <P>
 * 
 * @author $Author: u07286 $
 * @version $Revision: 1.3 $
 * 
 */

public class WindowsNTAgent extends Agent implements SharedFolderMgr, AccessLogMgr {
    /** utilidad para interrogar el espacio libre en un disco */
    protected bubu.util.javadisk javaDisk;
    /** true si funciona en cluster */
    protected boolean clustered;
    /** true si soporta cuotas de QuotaAdvisor */
    protected boolean setquota;
    /** unidades permitidas para depositar unidades compartidas */
    protected String allowedDrives;

    /**
     * Constructor
     * 
     * @param params
     *            parámetros de configuración : <br>
     *            <li>0 = si su valor es "cluster" asume que está gestionando un
     *            servicio de cluster y no una máquina fisica</li> <li>1 = si su
     *            valor es "quota" asume que el sistema soporta el sistema de
     *            cuotas de QuotaAdvisor</li> <li>2 = inventario de unidades
     *            donde puede (letras separadas por espacios) ubicar unidades
     *            comportidas</li>
     */
    public WindowsNTAgent() throws java.rmi.RemoteException {
    }

    /**
     * inicialización. Enlaza con javadisk.dll para la gestión del espacio libre
     * en disco
     * @throws InternalErrorException 
     */
    public void init() throws InternalErrorException {
        try {
            javaDisk = new bubu.util.javadisk();
        } catch (Throwable e) {
            e.printStackTrace();
        }
        clustered = ("cluster".equalsIgnoreCase(getDispatcher().getParam0()));
        setquota = ("quota".equalsIgnoreCase(getDispatcher().getParam1()));
        allowedDrives = getDispatcher().getParam2();
        log.info("Iniciado Agente Windows NT", null, null);
        log.debug("Allowed drives = " + allowedDrives, null, null);
    }

    /**
     * Creación de carpetas compartidas. Asigna la unidad en función del espacio
     * libre disponible en las unidades indicadas en el tercer parámetro del
     * constructor.<BR>
     * En caso de no indicar unidades, el sistema buscará en las unidades
     * físicas de la máquina o en las unidades de disco del cluster.
     * 
     * @see FolderMgr#CreateFolder
     */
    public void createFolder(String folder, int type) throws java.rmi.RemoteException,
            es.caib.seycon.ng.exception.InternalErrorException {
        String array[];
        int i;
        String subdir;
        String drive = null;
        long freeSpace = 0;
        boolean found = false;
        File f;

        if (javaDisk == null)
            throw new InternalErrorException("Error inicializando javadisk.dll");

        // String thisHost = InetAddress.getLocalHost().getHostName();
        // Establecer la quota y verificar que el grupo o usuario existe
        log.info("Creating folder for {} type {}", folder,
                type == SharedFolderMgr.userFolderType ? "USER" : "GROUP");
        String server;
        if (type == SharedFolderMgr.userFolderType) {
            Usuari ui;
            try {
                ui = getServer().getUserInfo(folder, getCodi());
                if (!ui.getActiu().booleanValue() || ui.getTipusUsuari().equals("E")) {
                    log.info("User inactive. Folder not created", null, null);
                    return;
                }
                server = ui.getServidorHome();
            } catch (UnknownUserException e) {
                log.info("User inactive. Folder not created", null, null);
                return;// Ya ho hace falta crear la carpeta
            }
        } else {
            Grup gi;
            try {
                gi = getServer().getGroupInfo(folder, getCodi());
                server = gi.getNomServidorOfimatic();
            } catch (UnknownGroupException e) {
                log.info("Group inactive. Folder not created", null, null);
                return;// Ya ho hace falta crear la carpeta
            }
        }
        // Determina los drives disponibles
        if (allowedDrives != null) {
            Vector v = new Vector();
            java.util.StringTokenizer t = new java.util.StringTokenizer(allowedDrives);
            while (t.hasMoreTokens()) {
                v.addElement(t.nextToken() + ":\\");
            }
            array = new String[v.size()];
            v.copyInto(array);
        } else if (!clustered) {
            array = javaDisk.enumDrives();
        } else {
            Vector v = new Vector();
            try {
                InputStreamReader in;
                String linea;
                TimedProcess p = new TimedProcess(15000);
                p.execNoWait("cluster . res");
                p.consumeError();
                in = new InputStreamReader(p.getOutputStream());
                BufferedReader br = new BufferedReader(in);
                while ((linea = br.readLine()) != null) {
                    if (linea.length() > 43) {
                        String res = linea.substring(0, 21).trim();
                        String group = linea.substring(21, 42).trim();
                        if (group.equalsIgnoreCase(server)
                                && res.substring(0, 6).equalsIgnoreCase("Disco ")) {
                            v.addElement(res.substring(6, 7) + ":\\");
                            log.info("Drive = " + res.substring(6, 7) + ":", null, null);
                        }
                    }
                }
                p.join();
                in.close();
            } catch (java.io.IOException e) {
            } catch (TimedOutException e) {
                throw new InternalErrorException("Cluster service off-line");
            }
            array = new String[v.size()];
            v.copyInto(array);
        }
        if (log.isDebugEnabled()) {
            StringBuffer values = new StringBuffer("[");
            for (int j = 0; j < array.length; j++) {
                values.append(array[j]);
                values.append(" ");
            }
            values.append("]");
            log.debug("Allowed drives {} ", values, null);
        }

        // Asigna el tipo
        if (type == SharedFolderMgr.userFolderType)
            subdir = "export\\home";
        else
            subdir = "export\\group";
        // Determinar el PATH óptimo
        for (i = 0; i < array.length && !found; i++) {
            log.info("Testing drive " + array[i], null, null);
            if (javaDisk.driveType(array[i]).equals("fixed")) {
                f = new File(array[i] + subdir);
                if (f.isDirectory()) {
                    f = new File(f, folder);
                    if (f.isDirectory()) {
                        found = true;
                        drive = array[i];
                        log.debug("Directory found on {} ({})", array[i], f.getAbsoluteFile());
                    } else {
                        long fs = javaDisk.freeSpace(array[i]);
                        if (drive == null && fs > 1000000 || fs > freeSpace) {
                            freeSpace = fs;
                            drive = array[i];
                            log.debug("Drive {} {} bytes free)", array[i], new Long(fs));
                        } else {
                            log.debug("Drive {} ignored ({} bytes free)", array[i], new Long(fs));
                        }
                    }
                } else {
                    log.debug("Drive {} ignored (directory {} does not exist)", array[i], subdir);
                }
            } else {
                log.debug("Drive {} ignored (not fixed)", array[i], null);
            }
        }
        // Comprobar que se ha encontrado el PATH
        if (drive == null) {
            throw new InternalErrorException("No hay drives adecuados para crear " + subdir + "\\"
                    + folder);
        }
        // Crear el path
        log.info("Selected drive " + drive, null, null);
        f = new File(drive + subdir, folder);
        if (!f.isDirectory()) {
            // int intentos = 0;
            // boolean ok = false;
            // Comprueba que el cluster esté arriba
            if (clustered) {
                try {
                    TimedProcess p = new TimedProcess(2000);
                    p.exec("cluster . res");
                    if (p.getOutput().toLowerCase().indexOf("pending") >= 0
                            || p.getOutput().toLowerCase().indexOf("offline") >= 0
                            || p.getOutput().toLowerCase().indexOf("error") >= 0) {
                        throw new InternalErrorException("Cluster service not ready:"
                                + p.getOutput());
                    }
                } catch (java.io.IOException e) {
                } catch (TimedOutException e) {
                    throw new InternalErrorException("Cluster service off-line");
                }
            }
            if (!f.mkdir()) {
                throw new InternalErrorException("Imposible crear directorio " + f.getPath());
            }
            int result = -1;
            // Quita permisos a Todos
            try {
                TimedProcess p = new TimedProcess(2000);
                p.exec("cacls \"" + f.getPath() + "\" /E /R Todos");
            } catch (Exception e) {
            }
            // Quita permisos a Everyone
            try {
                TimedProcess p = new TimedProcess(2000);
                p.exec("cacls \"" + f.getPath() + "\" /E /R Everyone");
            } catch (Exception e) {
            }
            // Asigna parmisos al usuario
            try {
                TimedProcess p = new TimedProcess(2000);
                result = p.exec("cacls \"" + f.getPath() + "\" /E /P \"" + folder + ":C\"");
                if (result != 0) {
                    f.delete();
                    throw new InternalErrorException("Error asignado ACLs " + p.getError());
                }
            } catch (Exception e) {
                f.delete();
                log.warn("Error procesando comando", e);
                e.printStackTrace(System.err);
                throw new InternalErrorException("Error asignado ACLs " + e.toString());
            }
            // Asigna quotas por defecto
            if (setquota) {
                /*
                 * try { TimedProcess p = new TimedProcess (60000); // p.exec
                 * ("setquota /a /o \""+f.getPath()+"\" /t 100MB"); p.exec
                 * ("setquota /a /o \""
                 * +f.getPath()+"\" /p 100000000 /r 10000000 /e"); if (quota !=
                 * 0) p.exec ("setquota /m /o \""+f.getPath()+"\" /p "+
                 * Long.toString(quota)+"000000 /e"); } catch (Exception e) {
                 * log
                 * .warn("Error thrown when setting quota with setquota: ",e);
                 * e.printStackTrace();
                 */
                try {
                    TimedProcess p = new TimedProcess(60000);
                    /*
                     * Se intenta asignar la quota con el nuevo comando
                     */
                    String command = "sealloc /a /o \"" + f.getPath()
                            + "\" /p:mb 100 /r:mb 10 /e /-w";
                    System.out.println("Command to execute :" + command);
                    p.exec(command);
                } catch (Exception eNew) {
                    log.warn("Error thrown when setting quota with sealloc: ", eNew);
                    f.delete();
                    eNew.printStackTrace(System.err);
                    throw new InternalErrorException("Error asignado Quotas " + eNew.toString());
                }
                // }
            }
            // Comparte el recurso
            if (result == 0) {
                TimedProcess p = new TimedProcess(10000);
                try {
                    result = p.exec("net share " + folder + "=\"" + f.getPath()
                            + "\" /grant:Everyone,Full"); // Añadimos grant
                                                          // everyone full
                                                          // (windows 2003)
                    if (result != 0 && p.getError().indexOf("2118") < 0) {
                        f.delete();
                        throw new InternalErrorException("Error compartiendo carpeta " + folder
                                + "=" + f.getPath() + " " + p.getOutput() + " " + p.getError());
                    }
                } catch (Exception e) {
                    f.delete();
                    log.warn("Error procesando comando", e);
                    e.printStackTrace(System.err);
                    throw new InternalErrorException("Error compartiendo carpeta " + folder + "="
                            + f.getPath() + " " + p.getOutput() + " " + p.getError());
                }
            }
        }
        // if (quota != 0)
        // {
        // throw new InternalErrorException ("Quotas no implementadas");
        // }
    }

    /**
     * Obtiene los registros de acceso a partir del visor de eventos del sistema
     * 
     * @see LogMgr#GetLogFromDate
     */
    public Collection<LogEntry> getLogFromDate(Date From) throws java.rmi.RemoteException,
            es.caib.seycon.ng.exception.InternalErrorException {
        // System.out.println ("Recogiendo logs");
        if (clustered)
            return null;
        try {
            int numLineas;
            TimedProcess p;
            InputStreamReader in;
            String linea;
            String args;
            SimpleDateFormat df = new SimpleDateFormat("yyyyMMddHHmmss");
            SimpleDateFormat df2 = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
            java.util.LinkedList<LogEntry> v = new LinkedList<LogEntry>();
            // Lazar el proceso

            if (From == null)
                args = "rel.exe 000000 xxxxxx";
            else {
                args = "rel.exe " + df.format(From) + " xxxxxx";
            }
            p = new TimedProcess(300000); // Como máximo cinco minutos
            try {
                p.execNoWait(args);
                p.consumeError();
                in = new InputStreamReader(p.getOutputStream());
                BufferedReader br = new BufferedReader(in);
                numLineas = 0;
                while ((linea = br.readLine()) != null) {
                    numLineas++;
                    String items[] = parseRelLine(linea);
                    LogEntry e = new LogEntry();
                    // ID de sesión
                    e.SessionId = items[0];
                    // LOGON / LOGOFF
                    if (items[1].equals("LOGON"))
                        e.type = LogEntry.LOGON;
                    else
                        e.type = LogEntry.LOGOFF;
                    // Fecha y hora
                    e.date = df2.parse(items[2]);
                    // Omitir el dominio
                    // Usuario
                    e.setUser( items[4].toLowerCase() );
                    // Servicio
                    if (items[5].equals("interactive"))
                        e.setProtocol( "LOGON" );
                    else if (items[5].equals("network"))
                        e.setProtocol( "SMB" );
                    else
                        e.setProtocol( "OTHER" );
                    // Máquina origen
                    if (e.getProtocol().equals("LOGON") && e.type == LogEntry.LOGON) {
                        if (items[6].equals("(null)"))
                            e.setHost( InetAddress.getLocalHost().getHostName() );
                        else if (items[6].startsWith("\\"))
                            e.setHost( items[6].substring(2).toLowerCase());
                        else
                            e.setHost( items[6].toLowerCase() );
                        e.setClient( items[7].toLowerCase() );
                    } else {
                        e.setHost( InetAddress.getLocalHost().getHostName() );
                        if (items[6].startsWith("\\"))
                            e.setClient(items[6].substring(2).toLowerCase());
                        else
                            e.setClient( items[6].toLowerCase() );
                    }
                    e.info = "";
                    if (!e.getUser().equals("") && ! e.getUser().endsWith("$")) {
                        if (v.size() >= 500)
                            v.removeLast();
                        v.push(e);
                    }
                }
                p.join();
            } catch (TimedOutException e) {
                if (v.size() == 0)
                    throw e;
            }
            // throw new TimedOutException ();
            LogEntry array[] = new LogEntry[v.size()];
            return v;
        } catch (Exception e) {
            throw new InternalErrorException(e.toString());
        }
    } // end-method

    // Analizar una línea de la tabla group.org_dir

    /**
     * interpreta las líneas producidas por el proceso rel
     * 
     * @param linea
     *            línea tal cual sale del proceso rel
     * @return vector con un elemento para cada columna de la línea
     */
    private String[] parseRelLine(String linea) {
        String result[] = new String[9];
        int i = 0;
        int columna = 0;
        while (i < result.length) {
            int columna1 = linea.indexOf("{", columna);
            if (columna1 == -1)
                columna1 = linea.indexOf("\n", columna);
            if (columna1 == -1)
                columna1 = linea.length();
            int columna2 = linea.indexOf("}", columna1);
            if (columna2 == -1)
                columna2 = linea.indexOf("\n", columna);
            if (columna2 == -1)
                columna2 = linea.length();
            try {
                result[i] = linea.substring(columna1 + 1, columna2);
            } catch (java.lang.StringIndexOutOfBoundsException e) {
                result[i] = "";
            }
            i++;
            columna = columna2 + 1;
        }
        return result;
    }

} // end-class

