package com.soffid.iam.sync.nas;

import java.io.IOException;
import java.io.PrintWriter;
import java.rmi.RemoteException;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.logging.LogFactory;

import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.msdtyp.SecurityDescriptor;
import com.hierynomus.msdtyp.SecurityDescriptor.Control;
import com.hierynomus.msdtyp.SecurityInformation;
import com.hierynomus.msdtyp.ace.ACE;
import com.hierynomus.msdtyp.ace.AceFlags;
import com.hierynomus.msdtyp.ace.AceTypes;
import com.hierynomus.mserref.NtStatus;
import com.hierynomus.msfscc.fileinformation.FileIdBothDirectoryInformation;
import com.hierynomus.msfscc.fileinformation.ShareInfo;
import com.hierynomus.mssmb2.SMB2CreateDisposition;
import com.hierynomus.mssmb2.SMB2Dialect;
import com.hierynomus.mssmb2.SMB2FileId;
import com.hierynomus.mssmb2.SMB2ShareAccess;
import com.hierynomus.mssmb2.SMBApiException;
import com.hierynomus.protocol.commons.EnumWithValue.EnumUtils;
import com.hierynomus.security.bc.BCSecurityProvider;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.common.SMBRuntimeException;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.Directory;
import com.hierynomus.smbj.share.DiskEntry;
import com.hierynomus.smbj.share.DiskShare;
import com.hierynomus.smbj.share.File;
import com.rapid7.client.dcerpc.RPCException;
import com.rapid7.client.dcerpc.dto.SID;
import com.rapid7.client.dcerpc.mssamr.SecurityAccountManagerService;
import com.rapid7.client.dcerpc.mssamr.dto.DomainHandle;
import com.rapid7.client.dcerpc.mssamr.dto.GroupHandle;
import com.rapid7.client.dcerpc.mssamr.dto.MembershipWithName;
import com.rapid7.client.dcerpc.mssamr.dto.MembershipWithUse;
import com.rapid7.client.dcerpc.mssamr.dto.ServerHandle;
import com.rapid7.client.dcerpc.mssamr.dto.UserHandle;
import com.rapid7.client.dcerpc.mssrvs.dto.NetShareInfo0;
import com.rapid7.client.dcerpc.mssrvs.dto.NetShareInfo1;
import com.rapid7.client.dcerpc.mssrvs.dto.NetShareInfo503;
import com.rapid7.client.dcerpc.msvcctl.dto.IServiceConfigInfo;
import com.rapid7.client.dcerpc.msvcctl.dto.ServiceConfigInfo;
import com.rapid7.client.dcerpc.msvcctl.dto.ServiceHandle;
import com.rapid7.client.dcerpc.msvcctl.dto.ServiceManagerHandle;
import com.rapid7.client.dcerpc.msvcctl.dto.enums.ServiceState;
import com.rapid7.client.dcerpc.msvcctl.dto.enums.ServiceType;
import com.rapid7.client.dcerpc.transport.RPCTransport;
import com.rapid7.client.dcerpc.transport.SMBTransportFactories;
import com.soffid.iam.api.Account;
import com.soffid.iam.api.HostService;
import com.soffid.iam.service.ApplicationService;
import com.soffid.iam.service.DispatcherService;
import com.soffid.iam.service.GroupService;
import com.soffid.msrpc.srvr.ServerService;
import com.soffid.msrpc.svcctl.EnumServiceStatus;
import com.soffid.msrpc.svcctl.ServiceControlManagerService;

import es.caib.seycon.ng.comu.Password;
import es.caib.seycon.ng.exception.InternalErrorException;

public class NASManager {
	ApplicationService appService = null;
	GroupService groupService = null;
	org.apache.commons.logging.Log log = LogFactory.getLog(getClass());
	
	DispatcherService dispatcherService = null;
	Set<SMB2ShareAccess> s = SMB2ShareAccess.ALL;
	Session adSession;
	
	String user;
	Password password;
	String domain;
	String host;
	private static SMBClient smbClient = null;
	private static SMBClient adClient = null;
	private Connection adConnection;
	private SmbConfig config;

	
	public NASManager (String domain, String host, String user, Password password) throws IOException
	{
		this.domain = domain;
		this.user = user;
		this.password = password;
		this.host = host;
		log.info("Initalizing NAS Manager");
		log.info("Domain: "+domain);
		log.info("User:   "+user);
		log.info("Server: "+host);
		disconnect();
	}
	
	public  void createFolder (String dir, String[] auth) throws Exception
	{ 
		String[] uncSplit = splitPath (dir);
		String server = uncSplit[0];
		String share = uncSplit[1];
		String path = uncSplit[2];
			
		try {
			connect();
			createShare ( server, share, path, new PrintWriter(System.out), auth);
		} catch (IOException | SMBRuntimeException e) {
			reconnect();
			createShare ( server, share, path, new PrintWriter(System.out), auth); // Try again
		}
	}

	public  void rm (String dir, String[] auth) throws Exception
	{ 
		String[] uncSplit = splitPath (dir);
		String server = uncSplit[0];
		String share = uncSplit[1];
		String path = uncSplit[2];

		try {
			connect();
			rmShare ( server, share, path, false, new PrintWriter(System.out), auth);
		} catch (IOException | SMBRuntimeException e) {
			reconnect();
			rmShare ( server, share, path, false, new PrintWriter(System.out), auth);
		}
	}

	public  void rmFolder (String dir, String[] auth) throws Exception
	{ 
		String[] uncSplit = splitPath (dir);
		String server = uncSplit[0];
		String share = uncSplit[1];
		String path = uncSplit[2];

		try {
			connect();
			rmShare ( server, share, path, true, new PrintWriter(System.out), auth);
		} catch (IOException | SMBRuntimeException e) {
			reconnect();
			rmShare ( server, share, path, true, new PrintWriter(System.out), auth);
		}
	}

	public boolean exists (String file, String[] auth) throws Exception
	{ 
		String[] uncSplit = splitPath (file);
		String server = uncSplit[0];
		String share = uncSplit[1];
		String path = uncSplit[2];

		try {
			connect();
			return exists ( server, share, path, new PrintWriter(System.out), auth);
		} catch (IOException | SMBRuntimeException e) {
			reconnect();
			return exists ( server, share, path, new PrintWriter(System.out), auth);
		}
	}

	public List<String[]> listShares (String server, String[] auth) throws Exception
	{ 
		try {
			connect();
			return listShares ( server, new PrintWriter(System.out), auth);
		} catch (IOException | SMBRuntimeException e) {
			reconnect();
			return listShares ( server, new PrintWriter(System.out), auth);
		}
	}

	public long getVolumeSize (String file, String[] auth) throws Exception
	{ 
		String[] uncSplit = splitPath (file);
		String server = uncSplit[0];
		String shareName = uncSplit[1];
		try {
			connect();
			return getVolumeSize ( server, shareName, new PrintWriter(System.out), auth);
		} catch (IOException | SMBRuntimeException e) {
			reconnect();
			return getVolumeSize ( server, shareName, new PrintWriter(System.out),   auth);
		}
	}

	public long getFreeSize (String file, String[] auth) throws Exception
	{ 
		String[] uncSplit = splitPath (file);
		String server = uncSplit[0];
		String shareName = uncSplit[1];
		try {
			connect();
			return getFreeSize(server, shareName, new PrintWriter(System.out), auth);
		} catch (IOException | SMBRuntimeException e) {
			reconnect();
			return getFreeSize(server, shareName, new PrintWriter(System.out), auth);
		}
	}

	public List<String[]> getAcl (String dir, String[] auth) throws Exception
	{ 
		String[] uncSplit = splitPath (dir);
		String server = uncSplit[0];
		String share = uncSplit[1];
		String path = uncSplit[2];

		try {
			connect();
			return getAcl ( server, share, path, new PrintWriter(System.out), auth);
		} catch (IOException | SMBRuntimeException e) {
			reconnect();
			return getAcl ( server, share, path, new PrintWriter(System.out), auth);
		}
	}

	public void addAcl (String dir, String samAccountName, String permission, String flags, String[] auth) 
			throws Exception
	{
		addAcl(dir, samAccountName, permission, flags, auth, false);
	}

	public void addAcl (String dir, String samAccountName, String permission, String flags, String[] auth, boolean recursive) throws Exception
	{ 
		String[] uncSplit = splitPath (dir);
		String server = uncSplit[0];
		String share = uncSplit[1];
		String path = uncSplit[2];

		try {
			connect();
			addAcl ( server, share, path, samAccountName, permission, flags, new PrintWriter(System.out), auth, recursive);
		} catch (IOException | SMBRuntimeException e) {
			reconnect();
			addAcl ( server, share, path, samAccountName, permission, flags, new PrintWriter(System.out), auth, recursive);
		}
	}

	public void setAcl (String dir, List<String[]> acl, String[] auth) throws Exception
	{ 
		String[] uncSplit = splitPath (dir);
		String server = uncSplit[0];
		String share = uncSplit[1];
		String path = uncSplit[2];

		try {
			connect();
			
			try {
				setAcl ( server, share, path, acl, new PrintWriter(System.out), auth, false);
			} catch (SMBApiException e0) {
				setAcl ( server, share, path, acl, new PrintWriter(System.out), auth, true);
			}
		} catch (IOException | SMBRuntimeException e) {
			reconnect();
			setAcl ( server, share, path, acl, new PrintWriter(System.out), auth, false);
		}
	}

	public void removeAcl (String dir, String samAccountName, String permission, String flags, String[] auth) throws Exception
	{ 
		String[] uncSplit = splitPath (dir);
		String server = uncSplit[0];
		String share = uncSplit[1];
		String path = uncSplit[2];

		try {
			connect();
			removeAcl ( server, share, path, samAccountName, permission, flags, new PrintWriter(System.out), auth);
		} catch (IOException | SMBRuntimeException e) {
			reconnect();
			removeAcl ( server, share, path, samAccountName, permission, flags, new PrintWriter(System.out), auth);
		}
	}



	public void removeAclInheritance(String dir, String[] auth) throws InternalErrorException, IOException {
		String[] uncSplit = splitPath (dir);
		String server = uncSplit[0];
		String share = uncSplit[1];
		String path = uncSplit[2];

		try {
			connect();
			removeAclInheritance ( server, share, path, new PrintWriter(System.out), auth);
		} catch (IOException | SMBRuntimeException e) {
			reconnect();
			removeAclInheritance ( server, share, path, new PrintWriter(System.out), auth);
		}
	}

	public void setOwner (String dir, String samAccountName, String[] auth) throws Exception
	{ 
		String[] uncSplit = splitPath (dir);
		String server = uncSplit[0];
		String share = uncSplit[1];
		String path = uncSplit[2];

		try {
			connect();
			setOwner ( server, share, path, samAccountName, new PrintWriter(System.out), auth);
		} catch (IOException | SMBRuntimeException e) {
			reconnect();
			setOwner ( server, share, path, samAccountName, new PrintWriter(System.out), auth);
		}
	}

	String[] splitPath (String unc) throws IOException
	{
		unc = unc.trim().replace('/', '\\');
		if ( !unc.startsWith("\\\\"))
			throw new IOException("Wrong unc "+unc+". It should start with \\\\");
		int p1 = unc.indexOf('\\', 2);
		if (p1 < 0)
			throw new IOException("Wrong unc "+unc+". It should contain a shared folder name");
		int p2 = unc.indexOf('\\', p1+1);
		String server = unc.substring(2, p1);
		String share = unc.substring(p1+1, p2 < 0 ? unc.length(): p2);
		String path = p2 < 0 ? "" : unc.substring(p2+1);
		return new String [] {server, share, path};
		
	}
	
	public List<String[]> listShares(String server,
			PrintWriter out, String[] auth) throws IOException, InternalErrorException {
		log.info("User:     "+auth[1]);
		log.info("Domain:   "+auth[0]);
		log.info("Server:   "+server);

		try (final Connection smbConnection = smbClient.connect(server)) {
		    final AuthenticationContext smbAuthenticationContext = new AuthenticationContext(auth[1], auth[2].toCharArray(), auth[0]);
		    final Session session = smbConnection.authenticate(smbAuthenticationContext);

		    RPCTransport transport2 = SMBTransportFactories.SRVSVC.getTransport(session);
		    ServerService srv = new ServerService(transport2);
		    List<String[]> l = new LinkedList<>();
		    for (NetShareInfo503 share: srv.getShares503()) {
		    	l.add(new String[] {share.getNetName(), share.getRemark(), Integer.toString(share.getType()), share.getServerName()});
		    }
		    return l;
		}
	}

	private long getVolumeSize(String server, String shareName, PrintWriter printWriter, String[] auth) throws IOException {
		log.info("User:     "+auth[1]);
		log.info("Domain:   "+auth[0]);
		log.info("Server:   "+server);
		log.info("Share:    "+shareName);

		try (final Connection smbConnection = smbClient.connect(server)) {
		    final AuthenticationContext smbAuthenticationContext = new AuthenticationContext(auth[1], auth[2].toCharArray(), auth[0]);
		    final Session session = smbConnection.authenticate(smbAuthenticationContext);

			try (DiskShare share = (DiskShare) session.connectShare(shareName)) {
		    	Directory of = null;
		    	ShareInfo i = share.getShareInformation();
		    	return i.getTotalSpace();
			}
		}
	}

	private long getFreeSize(String server, String shareName, PrintWriter printWriter, String[] auth) throws IOException {
		log.info("User:     "+auth[1]);
		log.info("Domain:   "+auth[0]);
		log.info("Server:   "+server);
		log.info("Share:    "+shareName);

		try (final Connection smbConnection = smbClient.connect(server)) {
		    final AuthenticationContext smbAuthenticationContext = new AuthenticationContext(auth[1], auth[2].toCharArray(), auth[0]);
		    final Session session = smbConnection.authenticate(smbAuthenticationContext);
		    
			try (DiskShare share = (DiskShare) session.connectShare(shareName)) {
		    	Directory of = null;
		    	ShareInfo i = share.getShareInformation();
		    	return i.getFreeSpace();
			}
		}
	}


	public void createShare(String server, String shareName, String path,
			PrintWriter out, String[] auth) throws IOException, InternalErrorException {
		log.info("User:     "+auth[1]);
		log.info("Domain:   "+auth[0]);
		log.info("Server:   "+server);
		log.info("Share:    "+shareName);

		try (final Connection smbConnection = smbClient.connect(server)) {
		    final AuthenticationContext smbAuthenticationContext = new AuthenticationContext(auth[1], auth[2].toCharArray(), auth[0]);
		    final Session session = smbConnection.authenticate(smbAuthenticationContext);
		    EnumSet<AccessMask> access;
			try (DiskShare share = (DiskShare) session.connectShare(shareName)) {
		    	Directory of = null;
		    	if ( ! share.folderExists(path))
		    	{
		    		of = share.openDirectory(path, EnumSet.of(AccessMask.GENERIC_ALL, AccessMask.READ_CONTROL,AccessMask.WRITE_DAC,AccessMask.WRITE_OWNER), 
			    				null,  s, SMB2CreateDisposition.FILE_OPEN_IF, null);
		    		of.close();
		    	}
			}
		}
	}

	public void rmShare(String server, String shareName, String path,
			boolean recursive, PrintWriter out, String auth[]) throws IOException, InternalErrorException {

		try (final Connection smbConnection = smbClient.connect(server)) {
		    final AuthenticationContext smbAuthenticationContext = new AuthenticationContext(auth[1], auth[2].toCharArray(), auth[0]);
		    final Session session = smbConnection.authenticate(smbAuthenticationContext);
		    EnumSet<AccessMask> access;
			try (DiskShare share = (DiskShare) session.connectShare(shareName)) {
		    	Directory of = null;
		    	if (share.folderExists(path) && recursive)
		    		recursiveRemove(share, path, auth[1], out);
		    	else if (share.folderExists(path))
		    		share.rmdir(path, false);
		    	else if (share.fileExists(path))
		    		share.rmdir(path, false);
			}
		}
	}

	private void recursiveRemove(DiskShare share, String path, String auth, PrintWriter out) throws IOException, InternalErrorException {
		setDirectoryOwner(share, path, auth, out);
		Directory of = share.openDirectory(path, EnumSet.of(AccessMask.READ_CONTROL,AccessMask.WRITE_DAC,AccessMask.WRITE_OWNER), 
				null,  s, SMB2CreateDisposition.FILE_OPEN, null);
		addAcl(of, path, auth, "GENERIC_ALL", "CONTAINER_INHERIT_ACE OBJECT_INHERIT_ACE");
		of.close();

		of = share.openDirectory(path, EnumSet.of(AccessMask.GENERIC_READ,AccessMask.GENERIC_WRITE), 
				null,  s, SMB2CreateDisposition.FILE_OPEN, null);
		for (FileIdBothDirectoryInformation child: of.list()) {
			if (! ".".equals(child.getFileName()) && ! "..".equals(child.getFileName())) {
				String fileName = path+"/"+child.getFileName();
				if (share.folderExists(fileName))
					recursiveRemove(share, fileName, auth, out);
				else if (share.fileExists(fileName)) {
					setFileOwner(fileName, share, auth, out);
					File of2 = share.openFile(fileName, EnumSet.of(AccessMask.READ_CONTROL,AccessMask.WRITE_DAC,AccessMask.WRITE_OWNER), 
							null,  s, SMB2CreateDisposition.FILE_OPEN, null);
					addAcl(of2, path, auth, "GENERIC_ALL", "CONTAINER_INHERIT_ACE OBJECT_INHERIT_ACE");
					of2.close();
					share.rm(fileName);					
				}
			}
		}
		of.close();
		share.rmdir(path, false);
	}


	public boolean exists (String server, String shareName, String path,
			PrintWriter out, String auth[]) throws IOException, InternalErrorException {

		try (final Connection smbConnection = smbClient.connect(server)) {
		    final AuthenticationContext smbAuthenticationContext = new AuthenticationContext(auth[1], auth[2].toCharArray(), auth[0]);
		    final Session session = smbConnection.authenticate(smbAuthenticationContext);
		    EnumSet<AccessMask> access;
			try (DiskShare share = (DiskShare) session.connectShare(shareName)) {
		    	Directory of = null;
		    	return share.fileExists(path) || share.folderExists(path);
			}
		}
	}


	public List<String[]> getAcl(String server, String shareName, String path,
			PrintWriter out, String[] auth) throws IOException, InternalErrorException {
		List<String[]> acl = new LinkedList<String[]>();
		try (final Connection smbConnection = smbClient.connect(server)) {
		    final AuthenticationContext smbAuthenticationContext = new AuthenticationContext(auth[1], auth[2].toCharArray(), auth[0]);
		    final Session session = smbConnection.authenticate(smbAuthenticationContext);
		    EnumSet<AccessMask> access;
			try (DiskShare share = (DiskShare) session.connectShare(shareName)) {
		    	Directory of = null;
		    	if ( share.folderExists(path))
		    	{
		    		of = share.openDirectory(path, EnumSet.of(AccessMask.GENERIC_ALL, AccessMask.READ_CONTROL,AccessMask.WRITE_DAC,AccessMask.WRITE_OWNER), 
			    				null,  s, SMB2CreateDisposition.FILE_OPEN, null);
		    		if (of == null)
		    			return null;
		    		
			    	SecurityDescriptor sd = of.getSecurityInformation( EnumSet.of( SecurityInformation.DACL_SECURITY_INFORMATION) );

			    	for ( ACE ace: sd.getDacl().getAces())
			    	{
			    		com.hierynomus.msdtyp.SID sid = ace.getSid();
			    		String user = getNameOf (out, sid);
			    		String am = enumToString(ace.getAccessMask(), AccessMask.class);
			    		String inh = enumToString(ace.getAceHeader().getAceFlags());
			    		acl.add(new String[] {user, am, inh});
			    	}
		    	}
			}
		}
		return acl;
	}

	public void removeAcl(String server, String shareName, String path,
			String samAccountName, String permission, String flags,
			PrintWriter out, String[] auth) throws IOException, InternalErrorException {
		try (final Connection smbConnection = smbClient.connect(server)) {
		    final AuthenticationContext smbAuthenticationContext = new AuthenticationContext(auth[1], auth[2].toCharArray(), auth[0]);
		    final Session session = smbConnection.authenticate(smbAuthenticationContext);
			try (DiskShare share = (DiskShare) session.connectShare(shareName)) {
		    	Directory of = null;
		    	if ( share.folderExists(path))
		    	{
		    		of = share.openDirectory(path, EnumSet.of(AccessMask.GENERIC_ALL, AccessMask.READ_CONTROL,AccessMask.WRITE_DAC,AccessMask.WRITE_OWNER), 
			    				null,  s, SMB2CreateDisposition.FILE_OPEN, null);
		    		if (of == null)
		    			throw new IOException ("File "+path+" does not exist");
		    		
			    	SecurityDescriptor sd = of.getSecurityInformation( EnumSet.of( SecurityInformation.DACL_SECURITY_INFORMATION) );

			    	
			    	for ( Iterator<ACE> it = sd.getDacl().getAces().iterator(); it.hasNext();)
			    	{
			    		ACE ace = it.next();
			    		com.hierynomus.msdtyp.SID sid = ace.getSid();
			    		String user = getNameOf (out, sid);
			    		String am = enumToString(ace.getAccessMask(), AccessMask.class);
			    		String inh = enumToString(ace.getAceHeader().getAceFlags());
			    		if ( user.equals(samAccountName) &&
			    				(permission == null || permission.equals(am)) &&
			    				(flags == null || flags.equals(inh)))
			    		{
			    			it.remove();
			    		}
			    	}

			    	sd.getControl().clear();
			    	sd.getControl().addAll(EnumSet.of(Control.DP, Control.SR, Control.PD));
			    	of.setSecurityInformation(sd);

			    	of.close();
		    	}
			}
		}
	}

	public void removeAclInheritance(String server, String shareName, String path,
			PrintWriter out, String[] auth) throws IOException, InternalErrorException {
		try (final Connection smbConnection = smbClient.connect(server)) {
		    final AuthenticationContext smbAuthenticationContext = new AuthenticationContext(auth[1], auth[2].toCharArray(), auth[0]);
		    final Session session = smbConnection.authenticate(smbAuthenticationContext);
			try (DiskShare share = (DiskShare) session.connectShare(shareName)) {
		    	Directory of = null;
		    	if ( share.folderExists(path))
		    	{
		    		of = share.openDirectory(path, EnumSet.of(AccessMask.GENERIC_ALL, AccessMask.READ_CONTROL,AccessMask.WRITE_DAC,AccessMask.WRITE_OWNER), 
			    				null,  s, SMB2CreateDisposition.FILE_OPEN, null);
		    		if (of == null)
		    			throw new IOException ("File "+path+" does not exist");
		    		
			    	SecurityDescriptor sd = of.getSecurityInformation( EnumSet.of( SecurityInformation.DACL_SECURITY_INFORMATION) );

			    	for ( Iterator<ACE> it = sd.getDacl().getAces().iterator(); it.hasNext();)
			    	{
			    		ACE ace = it.next();
			    		if (ace.getAceHeader().getAceFlags().contains(AceFlags.INHERITED_ACE) )
			    			it.remove();
			    	}

			    	sd.getControl().clear();
			    	sd.getControl().addAll(EnumSet.of(Control.DP, Control.SR, Control.PD));
			    	of.setSecurityInformation(sd);

			    	of.close();
		    	}
			}
		}
		return;
	}

	public void addAcl(String server, String shareName, String path,
			String samAccountName, String permission, String flags,
			PrintWriter out, String[] auth, boolean recursive) throws IOException, InternalErrorException {
		try (final Connection smbConnection = smbClient.connect(server)) {
		    final AuthenticationContext smbAuthenticationContext = new AuthenticationContext(auth[1], auth[2].toCharArray(), auth[0]);
		    final Session session = smbConnection.authenticate(smbAuthenticationContext);
			try (DiskShare share = (DiskShare) session.connectShare(shareName)) {
		    	DiskEntry of = null;
		    	addAclRecursively(path, samAccountName, permission, flags, share, recursive);
			}
		}
	}

	 
	public void setAcl(String server, String shareName, String path,
			List<String[]> acl,
			PrintWriter out, String[] auth, boolean force) throws IOException, InternalErrorException {
		try (final Connection smbConnection = smbClient.connect(server)) {
		    final AuthenticationContext smbAuthenticationContext = new AuthenticationContext(auth[1], auth[2].toCharArray(), auth[0]);
		    final Session session = smbConnection.authenticate(smbAuthenticationContext);
			try (DiskShare share = (DiskShare) session.connectShare(shareName)) {
		    	DiskEntry of = null;
				if ( share.folderExists(path))
				{
					if (force) {
						setDirectoryOwner(share, path, auth[1], out);
						of = share.openDirectory(path, EnumSet.of(AccessMask.READ_CONTROL,AccessMask.WRITE_DAC,AccessMask.WRITE_OWNER), 
								null,  s, SMB2CreateDisposition.FILE_OPEN, null);
						addAcl(of, path, auth[1], "GENERIC_ALL", "CONTAINER_INHERIT_ACE OBJECT_INHERIT_ACE");
						of.close();
					}
					of = share.openDirectory(path, EnumSet.of(AccessMask.READ_CONTROL,AccessMask.WRITE_DAC,AccessMask.WRITE_OWNER), 
								null,  s, SMB2CreateDisposition.FILE_OPEN, null);
					setAcl(of, path, acl);
					of.close();
				}
				if ( share.fileExists(path))
				{
					if (force) {
						setFileOwner(path, share, auth[1], out);
						of = share.openDirectory(path, EnumSet.of(AccessMask.READ_CONTROL,AccessMask.WRITE_DAC,AccessMask.WRITE_OWNER), 
								null,  s, SMB2CreateDisposition.FILE_OPEN, null);
						addAcl(of, path, auth[1], "GENERIC_ALL", "CONTAINER_INHERIT_ACE OBJECT_INHERIT_ACE");
						of.close();
					}
					of = share.openFile(path, EnumSet.of(AccessMask.READ_CONTROL,AccessMask.WRITE_DAC,AccessMask.WRITE_OWNER), 
								null,  s, SMB2CreateDisposition.FILE_OPEN, null);
					setAcl(of, path, acl);
					of.close();
				}
			}
		}
	}

	public void addAclRecursively(String path, String samAccountName, String permission, String flags, DiskShare share, boolean recursive)
			throws IOException, InternalErrorException {
		DiskEntry of;
		if ( share.folderExists(path))
		{
			of = share.openDirectory(path, EnumSet.of(AccessMask.GENERIC_ALL, AccessMask.READ_CONTROL,AccessMask.WRITE_DAC,AccessMask.WRITE_OWNER), 
						null,  s, SMB2CreateDisposition.FILE_OPEN, null);
			addAcl(of, path, samAccountName, permission, flags);
			if (recursive) {
				for (FileIdBothDirectoryInformation child: share.list(path)) {
					if (! ".".equals(child.getFileName()) && ! "..".equals(child.getFileName()))
						addAclRecursively(path+"/"+child.getFileName(), samAccountName, permission, flags, share, recursive);
				}
			}
			of.close();
		}
		else if ( share.fileExists(path))
		{
			of = share.openFile(path, EnumSet.of(AccessMask.GENERIC_ALL, AccessMask.READ_CONTROL,AccessMask.WRITE_DAC,AccessMask.WRITE_OWNER), 
						null,  s, SMB2CreateDisposition.FILE_OPEN, null);
			addAcl(of, path, samAccountName, permission, flags);
			of.close();
		}
	}

	public void addAcl(DiskEntry of, String path, String samAccountName, String permission, String flags)
			throws IOException, InternalErrorException {
		if (of == null)
			throw new IOException ("File "+path+" does not exist");
		
		SecurityDescriptor sd = of.getSecurityInformation( EnumSet.of( SecurityInformation.DACL_SECURITY_INFORMATION) );

		String userSid = getSid(samAccountName);
		if (userSid == null)
			throw new InternalErrorException ("Unable to find "+samAccountName+"'s SID");

		Set<AceFlags> inheritFlags = (Set<AceFlags>) stringToEnum(flags, AceFlags.class);
		Set<AccessMask> accessMasks = (Set<AccessMask>) stringToEnum(permission, AccessMask.class);
		ACE ace = AceTypes.accessAllowedAce( inheritFlags,
					accessMasks , 
					com.hierynomus.msdtyp.SID.fromString(userSid));
		sd.getDacl().getAces().add(0, ace);
		
		normalizeAces(sd.getDacl().getAces());
		
		sd.getControl().clear();
		sd.getControl().addAll(EnumSet.of(Control.DP, Control.SR, Control.PD));
		of.setSecurityInformation(sd);
	}
	

	public void setAcl(DiskEntry of, String path, List<String[]> acl)
			throws IOException, InternalErrorException {
		if (of == null)
			throw new IOException ("File "+path+" does not exist");
		
		SecurityDescriptor sd = of.getSecurityInformation( EnumSet.of( SecurityInformation.DACL_SECURITY_INFORMATION) );

		sd.getDacl().getAces().clear();

		for (String[] entry: acl) {
			String userSid = getSid(entry[0]);
			if (userSid == null)
				throw new InternalErrorException ("Unable to find "+entry[0]+"'s SID");
			
			Set<AceFlags> inheritFlags = (Set<AceFlags>) stringToEnum(entry[2], AceFlags.class);
			Set<AccessMask> accessMasks = (Set<AccessMask>) stringToEnum(entry[1], AccessMask.class);
			ACE ace = AceTypes.accessAllowedAce( inheritFlags,
					accessMasks , 
					com.hierynomus.msdtyp.SID.fromString(userSid));
			sd.getDacl().getAces().add(ace);
		}
		
		normalizeAces(sd.getDacl().getAces());
		
		
		sd.getControl().clear();
		sd.getControl().addAll(EnumSet.of(Control.DP, Control.SR, Control.PD));
		of.setSecurityInformation(sd);
	}
	

	private void normalizeAces(List<ACE> aces) {
		Set<String> used = new HashSet<>();
		for (Iterator<ACE> iterator = aces.iterator(); iterator.hasNext();) {
			ACE ace = iterator.next();
    		com.hierynomus.msdtyp.SID sid = ace.getSid();
    		String am = enumToString(ace.getAccessMask(), AccessMask.class);
    		String inh = enumToString(ace.getAceHeader().getAceFlags());
    		String hash = sid.toString() + " / "+am + " / " +inh; 
    		if (used.contains(hash))
    			iterator.remove();
    		else
    			used.add(hash);
		}
		
	}

	public void setOwner(String server, String shareName, String path,
			String samAccountName, 
			PrintWriter out, String[] auth) throws IOException, InternalErrorException {
		try (final Connection smbConnection = smbClient.connect(server)) {
		    final AuthenticationContext smbAuthenticationContext = new AuthenticationContext(auth[1], auth[2].toCharArray(), auth[0]);
		    final Session session = smbConnection.authenticate(smbAuthenticationContext);
			try (DiskShare share = (DiskShare) session.connectShare(shareName)) {
		    	if ( share.folderExists(path))
		    	{
		    		setDirectoryOwner(share, path, samAccountName, out);
		    	}
		    	else if ( share.fileExists(path))
		    	{
	    			setFileOwner(path, share, samAccountName, out);
		    	}
			}
		}
		return;
	}

	public void setFileOwner(String path, DiskShare share, String samAccountName, PrintWriter out)
			throws IOException, InternalErrorException {
		File of = share.openFile(path, EnumSet.of(AccessMask.WRITE_OWNER), 
				null,  s, SMB2CreateDisposition.FILE_OPEN, null);
		if (of == null)
			throw new IOException ("File "+path+" does not exist");
		
		String userSid = getSid(samAccountName);
		if (userSid == null)
			throw new InternalErrorException ("Unable to find "+user+"'s SID");
		
		SecurityDescriptor sd = new SecurityDescriptor(EnumSet.of(Control.NONE), 
				com.hierynomus.msdtyp.SID.fromString(userSid),
				null,
				null,
				null);
		of.setSecurityInformation(sd, EnumSet.of(SecurityInformation.OWNER_SECURITY_INFORMATION));
		of.close();
	}

	public void setDirectoryOwner(DiskShare share, String path, String samAccountName, PrintWriter out)
			throws IOException, InternalErrorException {
		Directory of = share.openDirectory(path, EnumSet.of(AccessMask.WRITE_OWNER), 
					null,  s, SMB2CreateDisposition.FILE_OPEN, null);
		if (of == null)
			throw new IOException ("File "+path+" does not exist");
		
//		SecurityDescriptor sd = of.getSecurityInformation( EnumSet.of( SecurityInformation.DACL_SECURITY_INFORMATION,
//				SecurityInformation.OWNER_SECURITY_INFORMATION, SecurityInformation.GROUP_SECURITY_INFORMATION) );

		String userSid = getSid(samAccountName);
		if (userSid == null)
			throw new InternalErrorException ("Unable to find "+user+"'s SID");
		
		SecurityDescriptor sd = new SecurityDescriptor(EnumSet.of(Control.NONE), 
				com.hierynomus.msdtyp.SID.fromString(userSid),
				null,
				null,
				null);
		of.setSecurityInformation(sd, EnumSet.of(SecurityInformation.OWNER_SECURITY_INFORMATION));
		of.close();
	}


	private String enumToString(long l, Class<? extends Enum> cl) {
		EnumSet<? extends Enum> set = EnumUtils.toEnumSet(l, cl);
		return enumToString(set);
	}

	public String enumToString(Set<? extends Enum> set) {
		StringBuffer accessString = new StringBuffer();
		for ( Enum am: set)
		{
			if (accessString.length() > 0)
				accessString.append(" ");
			accessString.append(am.name());
		}
		return accessString.toString();
	}
	
	public Set<? extends Enum> stringToEnum (String str, Class<? extends Enum> cl) {
		Set s = new HashSet();
		for (String part: str.split(" +"))
		{
			Object v = Enum.valueOf(cl, part);
			s.add(v);
		}
		return s;
	}

	private String getNameOf(PrintWriter out, com.hierynomus.msdtyp.SID userSid) throws IOException {
		RPCTransport transport2;
		try {
			transport2 = SMBTransportFactories.SAMSVC.getTransport(adSession);
		} catch (Exception e) {
			reconnect();
			transport2 = SMBTransportFactories.SAMSVC.getTransport(adSession);
		}
	    SecurityAccountManagerService sam = new SecurityAccountManagerService(transport2);
	    ServerHandle server = sam.openServer();
	    try {
		    for (MembershipWithName domains: sam.getDomainsForServer(server))
		    {
			    SID sid = sam.getSIDForDomain(server, domains.getName());
			    if (userSid.toString().startsWith( sid.toString()))
			    {
				    DomainHandle domain = sam.openDomain(server, sid);
				    
					String sids = userSid.toString();
					sids = sids.substring(sids.lastIndexOf("-")+1);
					try {
						UserHandle u = sam.openUser(domain, Integer.parseInt(sids));
						if (u == null)
						{
							return userSid.toString();
						}
						else
						{
							String name = sam.getUserAllInformation(u).getUserName();
							sam.closeHandle(u);
							return name;
						}
					} catch (Exception e) {
						try {
							GroupHandle g = sam.openGroup(domain, Integer.parseInt(sids));
							if (g == null)
							{
								return userSid.toString();
							}
							else
							{
								String name = sam.getGroupGeneralInformation(g).getName();
								sam.closeHandle(g);
								return name;
							}
						} catch (Exception e2 ) {
							return userSid.toString();
						}
					} finally {
						sam.closeHandle(domain);
					}
			    }
		    }
	    } finally {
	    	sam.closeHandle(server);
	    }
	    return userSid.toString();
	}

	public void connect() throws IOException {
		log.info("User:     "+user);
		log.info("Domain:   "+domain);
		log.info("Server:   "+host);

		if (smbClient == null)
		{
			config = SmbConfig.builder()
					.withDialects( 
							SMB2Dialect.SMB_2_1, SMB2Dialect.SMB_2_0_2 
//		            		,SMB2Dialect.SMB_3_0, SMB2Dialect.SMB_3_0_2, SMB2Dialect.SMB_3_1_1
							)
					.withSecurityProvider(new BCSecurityProvider())
					.build();
			smbClient = new SMBClient(config);
		}
		if (adClient == null)
		{
			config = SmbConfig.builder()
		            .withDialects( 
		            		SMB2Dialect.SMB_2_1, SMB2Dialect.SMB_2_0_2 
//		            		,SMB2Dialect.SMB_3_0, SMB2Dialect.SMB_3_0_2, SMB2Dialect.SMB_3_1_1
		            		)
		            .withSecurityProvider(new BCSecurityProvider())
		            .build();
			adClient = new SMBClient(config);
		}
		if (adConnection == null)
			adConnection = adClient.connect(host);
		if (adSession == null)
		{
			final AuthenticationContext adAuthenticationContext = new AuthenticationContext(user, password.getPassword().toCharArray(), domain);
			adSession = adConnection.authenticate(adAuthenticationContext);
		}
	}
	
	public void reconnect() throws IOException {
		disconnect();
		connect();
	}

	public void disconnect() {
		try {
			adSession.close();
		} catch (Exception e2) {
		}
		adSession = null;
		try {
			adConnection.close();
		} catch (Exception e2) {
		}
		adConnection = null;
		try {
			adClient.close();
		} catch (Exception e2) {
		}
		adClient = null;
		try {
			smbClient.close();
		} catch (Exception e2) {
		}
		smbClient = null;
	}

	
	public String getSid (String samAccountName) throws IOException 
	{
		String roleDomain = null;
		int i = samAccountName.indexOf('\\');
		if (i >= 0)
		{
//			roleDomain = groupName.substring(0,  i);
			samAccountName = samAccountName.substring(i+1);
		}
		
	    final RPCTransport transport2 = SMBTransportFactories.SAMSVC.getTransport(adSession);
	    SecurityAccountManagerService sam = new SecurityAccountManagerService(transport2);
	    ServerHandle server = sam.openServer();
	    try {
		    for (MembershipWithName domains: sam.getDomainsForServer(server))
		    {
		    	if (roleDomain == null || roleDomain.equalsIgnoreCase(domains.getName()))
		    	{
				    SID sid = sam.getSIDForDomain(server, domains.getName());
				    DomainHandle domain = sam.openDomain(server, sid);

				    try {
					    MembershipWithUse[] users = sam.lookupNamesInDomain(domain, samAccountName.toLowerCase());
					    for ( MembershipWithUse user: users)
					    {
					    	return sid.toString()+"-"+user.getRelativeID();		
					    }
				    } finally {				    
				    	sam.closeHandle(domain);
				    }
		    	}
		    }
	    } finally {
	    	sam.closeHandle(server);
	    }
	    return null;
	}
	
	public String getUser() {
		return user;
	}

	public void setUser(String user) {
		this.user = user;
	}

	public Password getPassword() {
		return password;
	}

	public void setPassword(Password password) {
		this.password = password;
	}

	public String getDomain() {
		return domain;
	}

	public void setDomain(String domain) {
		this.domain = domain;
	}

	public String getHost() {
		return host;
	}

	public void setHost(String host) {
		this.host = host;
	}

	
	public List<HostService> getServices(List<String> hosts) throws IOException {
		List<HostService> services = new LinkedList<>();
		for (String host: hosts) {
			try (final Connection smbConnection = smbClient.connect(host)) {
				Session session;
				final AuthenticationContext smbAuthenticationContext = new AuthenticationContext(user, password.getPassword().toCharArray(), domain);
				session = smbConnection.authenticate(smbAuthenticationContext);
			    final RPCTransport transport2 = SMBTransportFactories.SVCCTL.getTransport(session);
			    ServiceControlManagerService svc = new ServiceControlManagerService(transport2, session);
			    ServiceManagerHandle smh = svc.openServiceManagerHandle();
			    
			    List<EnumServiceStatus> s = svc.enumServicesStatus(smh, ServiceType.WIN32_OWN_PROCESS.getValue()+
			    			ServiceType.WIN32_SHARE_PROCESS.getValue(), ServiceState.STATE_ALL);
			    for (EnumServiceStatus service: s) {
			    	System.out.println(service.getServiceName()+" - "+service.getDisplayName());
			    	try {
			    		ServiceHandle h = svc.openServiceHandle(smh, service.getServiceName());
				    	IServiceConfigInfo config = svc.queryServiceConfig(h);
				    	System.out.println("   "+config.getServiceStartName());
				    	svc.closeServiceHandle(h);
				    	HostService hostService = new HostService();
				    	hostService.setHostName(host);
				    	hostService.setService(service.getServiceName());
				    	hostService.setAccountName(config.getServiceStartName());
				    	services.add(hostService);
			    	} catch (RPCException e) {
			    		
			    	} 
			    }
			    smbConnection.close();
			}
		}
		return services;
	}

	public void setServicePassword(String service, com.soffid.iam.api.Password password2) throws InternalErrorException {
		try (final Connection smbConnection = smbClient.connect(this.host)) {
		    final AuthenticationContext smbAuthenticationContext = new AuthenticationContext(user, password.getPassword().toCharArray(), domain);
		    final Session session = smbConnection.authenticate(smbAuthenticationContext);
			try {
				final RPCTransport transport2 = SMBTransportFactories.SVCCTL.getTransport(session);
				ServiceControlManagerService svc = new ServiceControlManagerService(transport2, session);
				ServiceManagerHandle smh = svc.openServiceManagerHandle();
				
				ServiceHandle h = svc.openServiceHandle(smh, service);
				IServiceConfigInfo config = svc.queryServiceConfig(h);
				ServiceConfigInfo config2 = new ServiceConfigInfo(
						config.getServiceType(),
						config.getStartType(),
						config.getErrorControl(),
						config.getBinaryPathName(), 
						config.getLoadOrderGroup(),
						config.getTagId(),
						config.getDependencies(),
						config.getServiceStartName(),
						config.getDisplayName(),
						password.getPassword());
				
				svc.changeServiceConfig(h, config2);
				svc.closeServiceHandle(h);
			} finally {
				session.close();
			}
		} catch (IOException e) {
			throw new InternalErrorException("Error fetching services", e);
		}
	}

	public String[] parseAuthData ( Map<String, Object> params) {
		if (params == null)
			return new String[] {this.domain, this.user, this.password.getPassword()};
		String user = (String) params.get("_auth_user");
		String password = (String) params.get("_auth_password");
		String domain = (String) params.get("_auth_domain");
		if (password != null)
			return new String [] {domain, user, password};
		else
			return new String[] {this.domain, this.user, this.password.getPassword()};
	}

}
