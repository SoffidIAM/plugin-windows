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

package com.soffid.iam.sync.agent2;

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

import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
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
import com.soffid.iam.api.Account;
import com.soffid.iam.api.AccountStatus;
import com.soffid.iam.api.Password;
import com.soffid.iam.api.Role;
import com.soffid.iam.api.RoleGrant;
import com.soffid.iam.api.User;
import com.soffid.iam.sync.agent.Agent;
import com.soffid.iam.sync.intf.ReconcileMgr2;
import com.soffid.iam.sync.intf.RoleMgr;
import com.soffid.iam.sync.intf.UserMgr;
import com.soffid.msrpc.samr.SamrService;

import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownRoleException;

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

	String serverName;
	String nbServerName;

	private Password password;

	private String domainName;

	private String user;
	
	SMBClient smbClient;
	/**
	 * Constructor
	 */
	public RemoteWindowsAgent() throws java.rmi.RemoteException {
	}

	@Override
	public void init() throws InternalErrorException {
		smbClient = new SMBClient();
		serverName = getSystem().getParam0();
		if (getSystem().getParam0() == null
				|| getSystem().getParam0().trim().length() == 0)
			throw new InternalErrorException("server name is empty");

		if (getSystem().getParam1() == null
				|| getSystem().getParam1().trim().length() == 0)
			throw new InternalErrorException("user name is empty");

		if (getSystem().getParam2() == null
				|| getSystem().getParam1().trim().length() == 0)
			throw new InternalErrorException("password is empty");

		user = getSystem().getParam1();
		if (user.contains("\\"))
		{
			String[] s = user.split("\\\\");
			
			domainName = s[0];
			user = s[1];
		}
		else
			domainName = serverName;
		password = Password.decode(getSystem().getParam2());

		try {
			final Connection smbConnection = smbClient.connect(serverName);
			try {
			    final AuthenticationContext smbAuthenticationContext = new AuthenticationContext(
			    		user, this.password.getPassword().toCharArray(), domainName);
			    final Session session = smbConnection.authenticate(smbAuthenticationContext);
			    final RPCTransport transport2 = SMBTransportFactories.SAMSVC.getTransport(session);
			    SamrService sam = new SamrService(transport2, session);
			    ServerHandle server = sam.openServer();
			    MembershipWithName[] domains = sam.getDomainsForServer(server);
			    for (MembershipWithName n: domains)
			    {
				    SID sid = sam.getSIDForDomain(server, n.getName());
			    	DomainHandle domainHandle = sam.openDomain(server, sid);
			    	log.info("Found domain "+n.getName());
			    }
			} finally {
				smbConnection.close();
			}
		} catch (IOException e) {
			throw new InternalErrorException ("Error connecting to "+serverName, e);
		}
	}

	public void updateRole(Role rol) throws RemoteException, InternalErrorException {
		try {
			final Connection smbConnection = smbClient.connect(serverName);
			try {
			    final AuthenticationContext smbAuthenticationContext = new AuthenticationContext(
			    		user, this.password.getPassword().toCharArray(), domainName);
			    final Session session = smbConnection.authenticate(smbAuthenticationContext);
			    final RPCTransport transport2 = SMBTransportFactories.SAMSVC.getTransport(session);
			    SamrService sam = new SamrService(transport2, session);
			    ServerHandle server = sam.openServer();
			    MembershipWithName[] domains = sam.getDomainsForServer(server);
			    for (MembershipWithName n: domains)
			    {
				    SID sid = sam.getSIDForDomain(server, n.getName());
			    	DomainHandle domainHandle = sam.openDomain(server, sid);
			    	log.info("Found domain "+n.getName());
			    	int rids[] ;
			    	try {
			    		rids = sam.lookupNames(domainHandle, new String[] { rol.getName() } );
			    	} catch (RPCException e) {
			    		if (e.getErrorCode() == SystemErrorCode.STATUS_NONE_MAPPED)
			    			continue;
			    		else
			    			throw e;
			    	}
//			    	role = sam.getDomainGroupInformationForDomain(domainHandle)
			    }
			} finally {
				smbConnection.close();
			}
		} catch (IOException e) {
			throw new InternalErrorException ("Error connecting to "+serverName, e);
		}
	}

	public void removeRole(String rolName, String dispatcher) throws RemoteException, InternalErrorException {
		// TODO Auto-generated method stub
		
	}

	public List<String> getAccountsList() throws RemoteException, InternalErrorException {
		// TODO Auto-generated method stub
		return null;
	}

	public Account getAccountInfo(String userAccount) throws RemoteException, InternalErrorException {
		// TODO Auto-generated method stub
		return null;
	}

	public List<String> getRolesList() throws RemoteException, InternalErrorException {
		// TODO Auto-generated method stub
		return null;
	}

	public Role getRoleFullInfo(String roleName) throws RemoteException, InternalErrorException {
		// TODO Auto-generated method stub
		return null;
	}

	public List<RoleGrant> getAccountGrants(String userAccount) throws RemoteException, InternalErrorException {
		// TODO Auto-generated method stub
		return null;
	}

	public void updateUser(Account account, User user) throws RemoteException, InternalErrorException {
		// TODO Auto-generated method stub
		
	}

	public void updateUser(Account account) throws RemoteException, InternalErrorException {
		// TODO Auto-generated method stub
		
	}

	public void removeUser(String userName) throws RemoteException, InternalErrorException {
		// TODO Auto-generated method stub
		
	}

	public void updateUserPassword(String userName, User userData, Password password, boolean mustchange)
			throws RemoteException, InternalErrorException {
		// TODO Auto-generated method stub
		
	}

	public boolean validateUserPassword(String userName, Password password)
			throws RemoteException, InternalErrorException {
		// TODO Auto-generated method stub
		return false;
	}

}
