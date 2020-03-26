package com.soffid.iam.sync.nas;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.msdtyp.SecurityDescriptor;
import com.hierynomus.msdtyp.SecurityDescriptor.Control;
import com.hierynomus.msdtyp.SecurityInformation;
import com.hierynomus.msdtyp.ace.ACE;
import com.hierynomus.msdtyp.ace.AceFlags;
import com.hierynomus.msdtyp.ace.AceTypes;
import com.hierynomus.mssmb2.SMB2CreateDisposition;
import com.hierynomus.mssmb2.SMB2ShareAccess;
import com.hierynomus.protocol.commons.EnumWithValue.EnumUtils;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.Directory;
import com.hierynomus.smbj.share.DiskShare;
import com.rapid7.client.dcerpc.dto.SID;
import com.rapid7.client.dcerpc.mssamr.SecurityAccountManagerService;
import com.rapid7.client.dcerpc.mssamr.dto.DomainHandle;
import com.rapid7.client.dcerpc.mssamr.dto.GroupHandle;
import com.rapid7.client.dcerpc.mssamr.dto.MembershipWithName;
import com.rapid7.client.dcerpc.mssamr.dto.MembershipWithUse;
import com.rapid7.client.dcerpc.mssamr.dto.ServerHandle;
import com.rapid7.client.dcerpc.mssamr.dto.UserHandle;
import com.rapid7.client.dcerpc.transport.RPCTransport;
import com.rapid7.client.dcerpc.transport.SMBTransportFactories;
import com.soffid.iam.service.ApplicationService;
import com.soffid.iam.service.DispatcherService;
import com.soffid.iam.service.GroupService;

import es.caib.seycon.ng.comu.Password;
import es.caib.seycon.ng.exception.InternalErrorException;

public class NASManager {
	ApplicationService appService = null;
	GroupService groupService = null;
	
	DispatcherService dispatcherService = null;
	Set<SMB2ShareAccess> s = SMB2ShareAccess.ALL;
	Session adSession;
	
	String user;
	Password password;
	String domain;
	String host;
	private static SMBClient smbClient = new SMBClient();
	private Connection adConnection;

	
	public NASManager (String domain, String host, String user, Password password) throws IOException
	{
		this.domain = domain;
		this.user = user;
		this.password = password;
		this.host = host;
		
		final AuthenticationContext adAuthenticationContext = new AuthenticationContext(user, password.getPassword().toCharArray(), domain);
		reconnect();
	}
	
	public  void createFolder (String dir) throws Exception
	{ 
		String[] uncSplit = splitPath (dir);
		String server = uncSplit[0];
		String share = uncSplit[1];
		String path = uncSplit[2];
			
		try {
			createShare ( server, share, path, new PrintWriter(System.out));
		} catch (IOException e) {
			reconnect();
			throw e;
		}
	}

	public  void rm (String dir) throws Exception
	{ 
		String[] uncSplit = splitPath (dir);
		String server = uncSplit[0];
		String share = uncSplit[1];
		String path = uncSplit[2];

		try {
			rmShare ( server, share, path, false, new PrintWriter(System.out));
		} catch (IOException e) {
			reconnect();
			throw e;
		}
	}

	public  void rmFolder (String dir) throws Exception
	{ 
		String[] uncSplit = splitPath (dir);
		String server = uncSplit[0];
		String share = uncSplit[1];
		String path = uncSplit[2];

		try {
			rmShare ( server, share, path, true, new PrintWriter(System.out));
		} catch (IOException e) {
			reconnect();
			throw e;
		}
	}

	public boolean exists (String file) throws Exception
	{ 
		String[] uncSplit = splitPath (file);
		String server = uncSplit[0];
		String share = uncSplit[1];
		String path = uncSplit[2];

		try {
			return exists ( server, share, path, new PrintWriter(System.out));
		} catch (IOException e) {
			reconnect();
			throw e;
		}
	}

	public List<String[]> getAcl (String dir) throws Exception
	{ 
		String[] uncSplit = splitPath (dir);
		String server = uncSplit[0];
		String share = uncSplit[1];
		String path = uncSplit[2];

		try {
			return getAcl ( server, share, path, new PrintWriter(System.out));
		} catch (IOException e) {
			reconnect();
			throw e;
		}
	}

	public void addAcl (String dir, String samAccountName, String permission, String flags) throws Exception
	{ 
		String[] uncSplit = splitPath (dir);
		String server = uncSplit[0];
		String share = uncSplit[1];
		String path = uncSplit[2];

		try {
			addAcl ( server, share, path, samAccountName, permission, flags, new PrintWriter(System.out));
		} catch (IOException e) {
			reconnect();
			throw e;
		}
	}

	public void removeAcl (String dir, String samAccountName, String permission, String flags) throws Exception
	{ 
		String[] uncSplit = splitPath (dir);
		String server = uncSplit[0];
		String share = uncSplit[1];
		String path = uncSplit[2];

		try {
			removeAcl ( server, share, path, samAccountName, permission, flags, new PrintWriter(System.out));
		} catch (IOException e) {
			reconnect();
			throw e;
		}
	}


	public void setOwner (String dir, String samAccountName) throws Exception
	{ 
		String[] uncSplit = splitPath (dir);
		String server = uncSplit[0];
		String share = uncSplit[1];
		String path = uncSplit[2];

		try {
			setOwner ( server, share, path, samAccountName, new PrintWriter(System.out));
		} catch (IOException e) {
			reconnect();
			throw e;
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
	
	public void createShare(String server, String shareName, String path,
			PrintWriter out) throws IOException, InternalErrorException {

		final SMBClient smbClient = new SMBClient();
		try (final Connection smbConnection = smbClient.connect(server)) {
		    final AuthenticationContext smbAuthenticationContext = new AuthenticationContext(user, password.getPassword().toCharArray(), domain);
		    final Session session = smbConnection.authenticate(smbAuthenticationContext);
		    EnumSet<AccessMask> access;
			try (DiskShare share = (DiskShare) session.connectShare(shareName)) {
		    	Directory of = null;
//		    	System.out.println("Testing path "+path);
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
			boolean recursive, PrintWriter out) throws IOException, InternalErrorException {

		final SMBClient smbClient = new SMBClient();
		try (final Connection smbConnection = smbClient.connect(server)) {
		    final AuthenticationContext smbAuthenticationContext = new AuthenticationContext(user, password.getPassword().toCharArray(), domain);
		    final Session session = smbConnection.authenticate(smbAuthenticationContext);
		    EnumSet<AccessMask> access;
			try (DiskShare share = (DiskShare) session.connectShare(shareName)) {
		    	Directory of = null;
//		    	System.out.println("Removing path "+path);
		    	if (share.folderExists(path) && recursive)
		    		share.rmdir(path, true);
		    	else if (share.folderExists(path))
		    		share.rmdir(path, false);
		    	else if (share.fileExists(path))
		    		share.rmdir(path, false);
			}
		}
	}

	public boolean exists (String server, String shareName, String path,
			PrintWriter out) throws IOException, InternalErrorException {

		final SMBClient smbClient = new SMBClient();
		try (final Connection smbConnection = smbClient.connect(server)) {
		    final AuthenticationContext smbAuthenticationContext = new AuthenticationContext(user, password.getPassword().toCharArray(), domain);
		    final Session session = smbConnection.authenticate(smbAuthenticationContext);
		    EnumSet<AccessMask> access;
			try (DiskShare share = (DiskShare) session.connectShare(shareName)) {
		    	Directory of = null;
//		    	System.out.println("Testing path "+path);
		    	return share.fileExists(path) || share.folderExists(path);
			}
		}
	}


	public List<String[]> getAcl(String server, String shareName, String path,
			PrintWriter out) throws IOException, InternalErrorException {
		List<String[]> acl = new LinkedList<String[]>();
		try (final Connection smbConnection = smbClient.connect(server)) {
		    final AuthenticationContext smbAuthenticationContext = new AuthenticationContext(user, password.getPassword().toCharArray(), domain);
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
		    		
			    	SecurityDescriptor sd = of.getSecurityInformation( EnumSet.of( SecurityInformation.DACL_SECURITY_INFORMATION,
			    			SecurityInformation.OWNER_SECURITY_INFORMATION, SecurityInformation.GROUP_SECURITY_INFORMATION) );

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
			PrintWriter out) throws IOException, InternalErrorException {
		try (final Connection smbConnection = smbClient.connect(server)) {
		    final AuthenticationContext smbAuthenticationContext = new AuthenticationContext(user, password.getPassword().toCharArray(), domain);
		    final Session session = smbConnection.authenticate(smbAuthenticationContext);
			try (DiskShare share = (DiskShare) session.connectShare(shareName)) {
		    	Directory of = null;
		    	if ( share.folderExists(path))
		    	{
		    		of = share.openDirectory(path, EnumSet.of(AccessMask.GENERIC_ALL, AccessMask.READ_CONTROL,AccessMask.WRITE_DAC,AccessMask.WRITE_OWNER), 
			    				null,  s, SMB2CreateDisposition.FILE_OPEN, null);
		    		if (of == null)
		    			throw new IOException ("File "+path+" does not exist");
		    		
			    	SecurityDescriptor sd = of.getSecurityInformation( EnumSet.of( SecurityInformation.DACL_SECURITY_INFORMATION,
			    			SecurityInformation.OWNER_SECURITY_INFORMATION, SecurityInformation.GROUP_SECURITY_INFORMATION) );

			    	
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

	public void addAcl(String server, String shareName, String path,
			String samAccountName, String permission, String flags,
			PrintWriter out) throws IOException, InternalErrorException {
		try (final Connection smbConnection = smbClient.connect(server)) {
		    final AuthenticationContext smbAuthenticationContext = new AuthenticationContext(user, password.getPassword().toCharArray(), domain);
		    final Session session = smbConnection.authenticate(smbAuthenticationContext);
			try (DiskShare share = (DiskShare) session.connectShare(shareName)) {
		    	Directory of = null;
		    	if ( share.folderExists(path))
		    	{
		    		of = share.openDirectory(path, EnumSet.of(AccessMask.GENERIC_ALL, AccessMask.READ_CONTROL,AccessMask.WRITE_DAC,AccessMask.WRITE_OWNER), 
			    				null,  s, SMB2CreateDisposition.FILE_OPEN, null);
		    		if (of == null)
		    			throw new IOException ("File "+path+" does not exist");
		    		
			    	SecurityDescriptor sd = of.getSecurityInformation( EnumSet.of( SecurityInformation.DACL_SECURITY_INFORMATION,
			    			SecurityInformation.OWNER_SECURITY_INFORMATION, SecurityInformation.GROUP_SECURITY_INFORMATION) );

			    	String userSid = getSid(samAccountName);
			    	if (userSid == null)
			    		throw new InternalErrorException ("Unable to finde "+user+"'s SID");
//			    	System.out.println("Role SID for "+user+": "+userSid);

			    	Set<AceFlags> inheritFlags = (Set<AceFlags>) stringToEnum(flags, AceFlags.class);
			    	Set<AccessMask> accessMasks = (Set<AccessMask>) stringToEnum(permission, AccessMask.class);
					ACE ace = AceTypes.accessAllowedAce( inheritFlags,
								accessMasks , 
								com.hierynomus.msdtyp.SID.fromString(userSid));
			    	sd.getDacl().getAces().add(ace);
			    	sd.getControl().clear();
			    	sd.getControl().addAll(EnumSet.of(Control.DP, Control.SR, Control.PD));
			    	of.setSecurityInformation(sd);
			    	of.close();
		    	}
			}
		}
		return;
	}

	public void setOwner(String server, String shareName, String path,
			String samAccountName, 
			PrintWriter out) throws IOException, InternalErrorException {
		try (final Connection smbConnection = smbClient.connect(server)) {
		    final AuthenticationContext smbAuthenticationContext = new AuthenticationContext(user, password.getPassword().toCharArray(), domain);
		    final Session session = smbConnection.authenticate(smbAuthenticationContext);
			try (DiskShare share = (DiskShare) session.connectShare(shareName)) {
		    	Directory of = null;
		    	if ( share.folderExists(path))
		    	{
		    		of = share.openDirectory(path, EnumSet.of(AccessMask.GENERIC_ALL, AccessMask.READ_CONTROL,AccessMask.WRITE_DAC,AccessMask.WRITE_OWNER), 
			    				null,  s, SMB2CreateDisposition.FILE_OPEN, null);
		    		if (of == null)
		    			throw new IOException ("File "+path+" does not exist");
		    		
			    	SecurityDescriptor sd = of.getSecurityInformation( EnumSet.of( SecurityInformation.DACL_SECURITY_INFORMATION,
			    			SecurityInformation.OWNER_SECURITY_INFORMATION, SecurityInformation.GROUP_SECURITY_INFORMATION) );

			    	com.hierynomus.msdtyp.SID ownerSid = sd.getOwnerSid();
			    	System.out.println("Owner sid = "+ownerSid);
			    	String owner = getNameOf(out, ownerSid);
			    	System.out.println("Owner = "+owner);
			    	
			    	String userSid = getSid(samAccountName);
			    	if (userSid == null)
			    		throw new InternalErrorException ("Unable to find "+user+"'s SID");
			    	
			    	sd = new SecurityDescriptor(sd.getControl(), com.hierynomus.msdtyp.SID.fromString(userSid),
			    			sd.getGroupSid(),
			    			sd.getSacl(),
			    			sd.getDacl());
			    	of.setSecurityInformation(sd);
			    	of.close();
		    	}
			}
		}
		return;
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

	public void reconnect() throws IOException {
		try {
			adSession.close();
			adConnection.close();
		} catch (Exception e2) {
		}
		adConnection = smbClient.connect(host);
		final AuthenticationContext adAuthenticationContext = new AuthenticationContext(user, password.getPassword().toCharArray(), domain);
		adSession = adConnection.authenticate(adAuthenticationContext);
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
	    for (MembershipWithName domains: sam.getDomainsForServer(server))
	    {
	    	if (roleDomain == null || roleDomain.equalsIgnoreCase(domains.getName()))
	    	{
			    SID sid = sam.getSIDForDomain(server, domains.getName());
			    DomainHandle domain = sam.openDomain(server, sid);
			    
			    MembershipWithUse[] users = sam.lookupNamesInDomain(domain, samAccountName);
			    for ( MembershipWithUse user: users)
			    {
			    	return sid.toString()+"-"+user.getRelativeID();		
			    }
	    	}
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

}
