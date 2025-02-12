package com.soffid.iam.sync.agent;

import java.io.IOException;
import java.rmi.RemoteException;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.mserref.NtStatus;
import com.hierynomus.mssmb2.SMBApiException;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.common.SMBRuntimeException;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.rapid7.client.dcerpc.RPCException;
import com.rapid7.client.dcerpc.dto.SID;
import com.rapid7.client.dcerpc.mserref.SystemErrorCode;
import com.rapid7.client.dcerpc.mssamr.dto.AliasGeneralInformation;
import com.rapid7.client.dcerpc.mssamr.dto.AliasHandle;
import com.rapid7.client.dcerpc.mssamr.dto.DomainHandle;
import com.rapid7.client.dcerpc.mssamr.dto.MembershipWithName;
import com.rapid7.client.dcerpc.mssamr.dto.ServerHandle;
import com.rapid7.client.dcerpc.mssamr.dto.UserAllInformation;
import com.rapid7.client.dcerpc.mssamr.dto.UserHandle;
import com.rapid7.client.dcerpc.transport.RPCTransport;
import com.rapid7.client.dcerpc.transport.SMBTransportFactories;
import com.soffid.iam.ServiceLocator;
import com.soffid.iam.api.Account;
import com.soffid.iam.api.AccountStatus;
import com.soffid.iam.api.DataType;
import com.soffid.iam.api.Password;
import com.soffid.iam.api.PasswordValidation;
import com.soffid.iam.api.Role;
import com.soffid.iam.api.RoleGrant;
import com.soffid.iam.api.SoffidObjectType;
import com.soffid.iam.api.User;
import com.soffid.iam.remote.RemoteServiceLocator;
import com.soffid.iam.service.AdditionalDataService;
import com.soffid.iam.sync.intf.ExtensibleObject;
import com.soffid.iam.sync.intf.ExtensibleObjectMapping;
import com.soffid.iam.sync.intf.ExtensibleObjectMgr;
import com.soffid.iam.sync.intf.ReconcileMgr2;
import com.soffid.iam.sync.intf.UserMgr;
import com.soffid.msrpc.samr.DispEntry;
import com.soffid.msrpc.samr.SamrService;
import com.soffid.msrpc.samr.UserInfo;

import es.caib.seycon.ng.comu.TypeEnumeration;
import es.caib.seycon.ng.config.Config;
import es.caib.seycon.ng.exception.InternalErrorException;

public class SimpleWindowsAgent extends Agent implements UserMgr, ReconcileMgr2, ExtensibleObjectMgr {
	final SMBClient smbClient = new SMBClient();
	protected String user;
	protected Password password;
	protected String server;
	private boolean onlyPassword;
	protected String domain;
	private Connection smbConnection;


	@Override
	public void init() throws Exception {
		super.init();
		log.info("Starting Simple SSH Agent agent on {}", getSystem().getName(), null);
		user = getSystem().getParam0();
		password = Password.decode(getSystem().getParam2());
		server = getSystem().getParam3();
		if (user.contains("\\")) {
			domain = user.substring(0, user.indexOf("\\"));
			user = user.substring(user.indexOf("\\")+1);
		} else {
			domain = server;
		}
		
		
		boolean debugEnabled = "true".equals(getSystem().getParam7());
		if (debugEnabled) setDebug(true);
		
		onlyPassword = "true".equals(getSystem().getParam4());

		
	}

	@Override
	public List<String> getAccountsList() throws RemoteException, InternalErrorException {
		List<String> accounts = new LinkedList<>();
		try {
			log.info("Getting accounts list");
			updateAccountsMetadata();
			Session session = getSession();
			try {
			    final RPCTransport transport2 = SMBTransportFactories.SAMSVC.getTransport(session);
			    SamrService sam = new SamrService(transport2, session);
			    ServerHandle serverHandle = sam.openServer();
			    MembershipWithName[] domains = sam.getDomainsForServer(serverHandle);
			    for (MembershipWithName n: domains)
			    {
				    SID sid = sam.getSIDForDomain(serverHandle, n.getName());
			    	DomainHandle domainHandle = sam.openDomain(serverHandle, sid);
			    	int [] r;
			    	try {
			    		List<DispEntry> users = sam.listUsers(domainHandle);
			    		for (DispEntry user: users) {
			    			accounts.add(user.getAccountName().getValue());
			    		}
			    	} catch (RPCException e) {
			    		if (e.getErrorCode() == SystemErrorCode.STATUS_NONE_MAPPED)
			    			continue;
			    		else
			    			throw e;
			    	}
			    }
			    return accounts;
			} finally {
				closeSession(session);
			}
		} catch (RPCException e) {
			throw new InternalErrorException("Error getting accounts list", e);
		} catch (IOException e) {
			throw new InternalErrorException("Error getting accounts list", e);
		}
	}

	private void updateAccountsMetadata() throws IOException, InternalErrorException {
		log.info("Checking metadata");
		
		if (getSystem().getId().longValue() == 0)
			return;
		
		AdditionalDataService ds = ! Config.getConfig().isServer() ? 
			new RemoteServiceLocator().getAdditionalDataService() :
			ServiceLocator.instance().getAdditionalDataService();
		checkMetadata("rid", TypeEnumeration.NUMBER_TYPE, "Internal id", ds);
		checkMetadata("gid", TypeEnumeration.NUMBER_TYPE, "Group id", ds);
		checkMetadata("home", TypeEnumeration.STRING_TYPE, "Home directory", ds);
		checkMetadata("comments", TypeEnumeration.STRING_TYPE, "Comments", ds);
	}

	long minOrder = 1;
	private void checkMetadata(String name, TypeEnumeration type, String description, AdditionalDataService ds) throws InternalErrorException {
		if (ds.findSystemDataType(getAgentName(), name) == null) {
			log.info("Creating "+name+" on "+getAgentName());
			DataType dt = new DataType();
			dt.setBuiltin(Boolean.FALSE);
			dt.setLabel(description);
			dt.setName(name);
			dt.setType(type);
			dt.setMultiValued(false);
			dt.setRequired(false);
			dt.setUnique(false);
			dt.setSystemName(getAgentName());
			for (DataType dt2: ds.findSystemDataTypes2(getAgentName())) {
				if (dt2.getOrder().longValue() >= minOrder)
					minOrder = dt2.getOrder().longValue()+1;
			}
			dt.setOrder( minOrder ++ );
			ds.create(dt);
		}
	}

	public void closeSession(Session session) {
		try {
			session.close();
		} catch (IOException e) {}
	}

	@Override
	public Account getAccountInfo(String userAccount) throws RemoteException, InternalErrorException {
		try {
			Session session = getSession();
			try {
			    final RPCTransport transport2 = SMBTransportFactories.SAMSVC.getTransport(session);
			    log.info("OPEN SAM SERVICE");
			    SamrService sam = new SamrService(transport2, session);
			    ServerHandle serverHandle = sam.openServer();
			    MembershipWithName[] domains = sam.getDomainsForServer(serverHandle);
			    for (MembershipWithName n: domains)
			    {
				    SID sid = sam.getSIDForDomain(serverHandle, n.getName());
			    	DomainHandle domainHandle = sam.openDomain(serverHandle, sid);
			    	if (isDebug())
			    		log.info("Searching user "+userAccount+" at SAM domain "+n.getName());
			    	int [] r;
			    	try {
			    		r = sam.lookupNames(domainHandle, new String[] {userAccount});
			    	} catch (RPCException e) {
			    		if (e.getErrorCode() == SystemErrorCode.STATUS_NONE_MAPPED)
			    			continue;
			    		else
			    			throw e;
			    	}
			    	for (int i: r) {
			    		if (isDebug())
			    			log.info("Opening user "+userAccount+" at SAM domain "+n.getName());
			    		UserHandle userHandle = null;
			    		try {
			    			userHandle = sam.openUser(domainHandle, i, 0x201DB);
				    		UserAllInformation userAllInformation = sam.getUserAllInformation(userHandle);
				    		Account acc = new Account();
				    		acc.setName(userAllInformation.getUserName());
				    		acc.setLoginName(userAllInformation.getUserName());
				    		acc.setDescription(userAllInformation.getFullName());
				    		acc.setAttributes(new HashMap<String,Object>());
				    		acc.getAttributes().put("rid", userAllInformation.getUserId());
				    		acc.getAttributes().put("gid", userAllInformation.getPrimaryGroupId());
				    		acc.getAttributes().put("home", userAllInformation.getHomeDirectory());
				    		acc.getAttributes().put("comments", userAllInformation.getAdminComment());
				    		if ((userAllInformation.getUserAccountControl() & 1) != 0)
				    		{
				    			acc.setDisabled(true);
				    			acc.setStatus(AccountStatus.DISABLED);
				    		} else {
				    			acc.setDisabled(false);
				    			acc.setStatus(AccountStatus.ACTIVE);
				    		}
				    		return acc;
			    		} catch (RPCException e) {
			    			if (e.getErrorCode() == SystemErrorCode.STATUS_ACCESS_DENIED)  {
			    				userHandle = sam.openUser(domainHandle, i, 0x2001B);
					    		UserAllInformation userAllInformation = sam.getUserAllInformation(userHandle);
					    		Account acc = new Account();
					    		acc.setName(userAllInformation.getUserName());
					    		acc.setLoginName(userAllInformation.getUserName());
					    		acc.setDescription(userAllInformation.getFullName());
					    		acc.setAttributes(new HashMap<String,Object>());
					    		acc.getAttributes().put("rid", userAllInformation.getUserId());
					    		acc.getAttributes().put("gid", userAllInformation.getPrimaryGroupId());
					    		acc.getAttributes().put("home", userAllInformation.getHomeDirectory());
					    		acc.getAttributes().put("comments", userAllInformation.getAdminComment());
					    		if ((userAllInformation.getUserAccountControl() & 1) != 0)
					    		{
					    			acc.setDisabled(true);
					    			acc.setStatus(AccountStatus.DISABLED);
					    		} else {
					    			acc.setDisabled(false);
					    			acc.setStatus(AccountStatus.ACTIVE);
					    		}
					    		return acc;
			    			}
		    				else
		    					throw e;
			    		} finally {
			    			if (userHandle != null)
			    				sam.closeHandle(userHandle);
			    		}
			    	}		    	
			    }
			} finally {
				closeSession(session);
			}
			return null;
		} catch (RPCException e) {
			throw new InternalErrorException("Error getting accounts list", e);
		} catch (IOException e) {
			throw new InternalErrorException("Error getting accounts list", e);
		}
	}

	@Override
	public List<String> getRolesList() throws RemoteException, InternalErrorException {
		List<String> groups = new LinkedList<>();
		try {
			Session session = getSession();
			try {
			    final RPCTransport transport2 = SMBTransportFactories.SAMSVC.getTransport(session);
			    SamrService sam = new SamrService(transport2, session);
			    ServerHandle serverHandle = sam.openServer();
			    MembershipWithName[] domains = sam.getDomainsForServer(serverHandle);
			    for (MembershipWithName n: domains)
			    {
				    SID sid = sam.getSIDForDomain(serverHandle, n.getName());
			    	DomainHandle domainHandle = sam.openDomain(serverHandle, sid);
			    	int [] r;
			    	try {
			    		MembershipWithName[] samrGroups = sam.getAliasesForDomain(domainHandle);
			    		for (MembershipWithName group: samrGroups) {
			    			groups.add(group.getName());
			    		}
			    	} catch (RPCException e) {
			    		if (e.getErrorCode() == SystemErrorCode.STATUS_NONE_MAPPED)
			    			continue;
			    		else
			    			throw e;
			    	}
			    }
			    return groups;
			} finally {
				closeSession(session);
			}
		} catch (RPCException e) {
			throw new InternalErrorException("Error getting accounts list", e);
		} catch (IOException e) {
			throw new InternalErrorException("Error getting accounts list", e);
		}
	}

	@Override
	public Role getRoleFullInfo(String roleName) throws RemoteException, InternalErrorException {
		try {
			Session session = getSession();
			try {
			    final RPCTransport transport2 = SMBTransportFactories.SAMSVC.getTransport(session);
			    log.info("OPEN SAM SERVICE");
			    SamrService sam = new SamrService(transport2, session);
			    ServerHandle serverHandle = sam.openServer();
			    MembershipWithName[] domains = sam.getDomainsForServer(serverHandle);
			    for (MembershipWithName n: domains)
			    {
				    SID sid = sam.getSIDForDomain(serverHandle, n.getName());
			    	DomainHandle domainHandle = sam.openDomain(serverHandle, sid);
			    	if (isDebug())
			    		log.info("Searching group "+roleName+" at SAM domain "+n.getName());
			    	int [] r;
			    	try {
			    		r = sam.lookupNames(domainHandle, new String[] {roleName});
			    	} catch (RPCException e) {
			    		if (e.getErrorCode() == SystemErrorCode.STATUS_NONE_MAPPED)
			    			continue;
			    		else
			    			throw e;
			    	}
			    	for (int i: r) {
			    		if (isDebug())
			    			log.info("Opening group "+roleName+" at SAM domain "+n.getName());
			    		AliasHandle groupHandle = sam.openAlias(domainHandle, i);
			    		try {
				    		AliasGeneralInformation gi = sam.getAliasGeneralInformation(groupHandle);
				    		Role role = new Role();
				    		role.setName(gi.getName());
				    		role.setDescription(gi.getAdminComment());
				    		return role;
			    		} finally {
			    			sam.closeHandle(groupHandle);
			    		}
			    	}		    	
			    }
			} finally {
				closeSession(session);
			}
			return null;
		} catch (RPCException e) {
			throw new InternalErrorException("Error getting accounts list", e);
		} catch (IOException e) {
			throw new InternalErrorException("Error getting accounts list", e);
		}
	}

	@Override
	public List<RoleGrant> getAccountGrants(String userAccount) throws RemoteException, InternalErrorException {
		try {
			Session session = getSession();
			try {
			    final RPCTransport transport2 = SMBTransportFactories.SAMSVC.getTransport(session);
			    log.info("OPEN SAM SERVICE");
			    SamrService sam = new SamrService(transport2, session);
			    ServerHandle serverHandle = sam.openServer();
			    MembershipWithName[] domains = sam.getDomainsForServer(serverHandle);
			    for (MembershipWithName n: domains)
			    {
				    SID sid = sam.getSIDForDomain(serverHandle, n.getName());
			    	DomainHandle domainHandle = sam.openDomain(serverHandle, sid);
			    	int [] r;
			    	try {
			    		r = sam.lookupNames(domainHandle, new String[] {userAccount});
			    	} catch (RPCException e) {
			    		if (e.getErrorCode() == SystemErrorCode.STATUS_NONE_MAPPED)
			    			continue;
			    		else
			    			throw e;
			    	}
			    	for (int i: r) {
			    		if (isDebug())
			    			log.info("Opening user "+userAccount+" at SAM domain "+n.getName());
			    		try {
			    			UserHandle userHandle;
				    		try {
				    			userHandle = sam.openUser(domainHandle, i, 0x201DB);
				    		} catch (RPCException e) {
				    			if (e.getErrorCode() == SystemErrorCode.STATUS_ACCESS_DENIED) 
				    				userHandle = sam.openUser(domainHandle, i, 0x20000);
			    				else
			    					throw e;
				    		}
				    		try {
				    			SID userSid = sid.resolveRelativeID(i);
						    	List<RoleGrant> rg = new LinkedList<>();
						    	for (MembershipWithName n2: domains) {
						    		SID sid2 = sam.getSIDForDomain(serverHandle, n2.getName());
						    		DomainHandle domainHandle2 = sam.openDomain(serverHandle, sid2);
							    	for (MembershipWithName alias: sam.getAliasesForDomain(domainHandle2)) {
							    		AliasHandle aliasHandle = sam.openAlias(domainHandle2, alias.getRelativeID());
							    		try {
								    		for (SID members: sam.getMembersInAlias(aliasHandle)) {
								    			if (members.equals(userSid)) {
								    				AliasGeneralInformation ai = sam.getAliasGeneralInformation(aliasHandle);
								    				if (ai != null) {
								    					RoleGrant g = new RoleGrant();
								    					g.setOwnerAccountName(userAccount);
								    					g.setOwnerSystem(getAgentName());
								    					g.setRoleName(ai.getName());
								    					g.setSystem(getAgentName());
								    					rg.add(g);
								    				}
								    			}
								    		}
							    		} finally {
							    			sam.closeHandle(aliasHandle);
							    		}
							    	}
					    		}
					    		return rg;
				    		} finally {
				    			sam.closeHandle(userHandle);
				    		}
			    		} catch (RPCException e) {
			    			if (e.getErrorCode() == SystemErrorCode.STATUS_ACCESS_DENIED) {
						    	return new LinkedList<>();
			    			}
			    			else
			    				throw e;
			    		}
			    	}		    	
			    }
			} finally {
				closeSession(session);
			}
			return null;
		} catch (RPCException e) {
			throw new InternalErrorException("Error getting accounts list", e);
		} catch (IOException e) {
			throw new InternalErrorException("Error getting accounts list", e);
		}
	}

	@Override
	public void updateUser(Account account, User user) throws RemoteException, InternalErrorException {
		if (onlyPassword)
			return;
		Collection<RoleGrant> perms = getServer().getAccountExplicitRoles(account.getName(), account.getSystem());
		try {
			Session session = getSession();
			try {
			    final RPCTransport transport2 = SMBTransportFactories.SAMSVC.getTransport(session);
			    SamrService sam = new SamrService(transport2, session);
			    ServerHandle serverHandle = sam.openServer();
			    MembershipWithName[] domains = sam.getDomainsForServer(serverHandle);
			    boolean found = false;
			    for (MembershipWithName n: domains)
			    {
				    SID sid = sam.getSIDForDomain(serverHandle, n.getName());
			    	DomainHandle domainHandle = sam.openDomain(serverHandle, sid);
			    	if (isDebug())
			    		log.info("Searching user "+account.getName()+" at SAM domain "+n.getName());
			    	int [] r;
			    	try {
			    		r = sam.lookupNames(domainHandle, new String[] {account.getName()});
			    		for (int i: r) {
			    			found = true;
			    			if (isDebug())
			    				log.info("Opening user "+account.getName()+" at SAM domain "+n.getName());
			    			UserHandle userHandle = sam.openUser(domainHandle, i, 0x000F07FF);
			    			updateUserAttributes(sam, userHandle, account);
			    			updateUserPermissions(sam, sid.resolveRelativeID(i), account, perms);
			    		}		    	
			    	} catch (RPCException e) {
			    		if (e.getErrorCode() == SystemErrorCode.STATUS_NONE_MAPPED) {
			    			
			    		} else {
			    			throw e;
			    		}
			    	}
			    }
			    if (!found && account.getStatus() != AccountStatus.REMOVED) {
				    SID sid = sam.getSIDForDomain(serverHandle, domains[0].getName());
			    	DomainHandle domainHandle = sam.openDomain(serverHandle, sid);
			    	UserHandle userHandle = sam.createUser(domainHandle, account.getName(), 0x201DB);
			    	UserInfo data = sam.queryUserInfo(userHandle);
	    			updateUserAttributes(sam, userHandle, account);
	    			updateUserPermissions(sam, sid.resolveRelativeID(data.getRid()), account, perms);
			    }
			} finally {
				closeSession(session);
			}
		} catch (RPCException e) {
			throw new InternalErrorException("Error getting accounts list", e);
		} catch (IOException e) {
			throw new InternalErrorException("Error getting accounts list", e);
		}
	}

	private void updateUserPermissions(SamrService sam, SID userSid, Account account,
			Collection<RoleGrant> perms) throws InternalErrorException, IOException {
		List<RoleGrant> currentPerms = getAccountGrants(account.getName());
		LinkedList<RoleGrant> newPerms = new LinkedList<RoleGrant>(perms);
		for (java.util.Iterator<RoleGrant> it = currentPerms.iterator(); it.hasNext();) {
			RoleGrant oldPerm = it.next();
			boolean found = false;
			for (java.util.Iterator<RoleGrant> it2 = newPerms.iterator(); it2.hasNext();) {
				RoleGrant newPerm = it2.next();
				if (newPerm.getRoleName().equals(oldPerm.getRoleName())) {
					found = true;
					it2.remove();
					break;
				}
			}
			if (!found) {
			    deleteAliasMember(sam, userSid, oldPerm.getRoleName());
			}
		}
		for (RoleGrant newPerm: newPerms) {
			addAliasMember(sam, userSid, newPerm.getRoleName());
		}
	}

	public void deleteAliasMember(SamrService sam, SID userSid, String groupName) throws IOException {
		ServerHandle serverHandle = sam.openServer();
		MembershipWithName[] domains = sam.getDomainsForServer(serverHandle);
		for (MembershipWithName n: domains)
		{
		    SID sid = sam.getSIDForDomain(serverHandle, n.getName());
			DomainHandle domainHandle = sam.openDomain(serverHandle, sid);
			if (isDebug())
				log.info("Searching alias "+groupName+" at SAM domain "+n.getName());
			int [] r;
			try {
				r = sam.lookupNames(domainHandle, new String[] {groupName});
				for (int i: r) {
					if (isDebug())
						log.info("Opening alias "+groupName+" at SAM domain "+n.getName());
					AliasHandle aliasHandle = sam.openAlias(domainHandle, i, (int) AccessMask.GENERIC_ALL.getValue());
					try {
						sam.deleteAliasMember(aliasHandle, userSid);
					} finally {
						sam.closeHandle(aliasHandle);
					}
				}		    	
			} catch (RPCException e) {
				if (e.getErrorCode() == SystemErrorCode.STATUS_NONE_MAPPED) {
					
				}
			}
		}
	}

	public void addAliasMember(SamrService sam, SID userSid, String roleName) throws IOException, InternalErrorException {
		ServerHandle serverHandle = sam.openServer();
		MembershipWithName[] domains = sam.getDomainsForServer(serverHandle);
		boolean foundAlias = false;
		for (MembershipWithName n: domains)
		{
		    SID sid = sam.getSIDForDomain(serverHandle, n.getName());
			DomainHandle domainHandle = sam.openDomain(serverHandle, sid);
			if (isDebug())
				log.info("Searching alias "+roleName+" at SAM domain "+n.getName());
			int [] r;
			try {
				r = sam.lookupNames(domainHandle, new String[] {roleName});
				for (int i: r) {
					if (isDebug())
						log.info("Opening alias "+roleName+" at SAM domain "+n.getName());
					AliasHandle aliasHandle = sam.openAlias(domainHandle, i, (int) AccessMask.GENERIC_ALL.getValue());
					try {
						sam.addAliasMember(aliasHandle, userSid);
					} finally {
						sam.closeHandle(aliasHandle);
					}
					foundAlias = true;
				}		    	
			} catch (RPCException e) {
				if (e.getErrorCode() == SystemErrorCode.STATUS_NONE_MAPPED) {
				}
			}
		}
		if (!foundAlias)
			throw new InternalErrorException("Cannot find local group "+roleName);
	}
	/** Flags 
	  	typedef [public,bitmap32bit] bitmap {
		ACB_DISABLED			= 0x00000001,  /- 1 = User account disabled -/
		ACB_HOMDIRREQ			= 0x00000002,  /- 1 = Home directory required -/
		ACB_PWNOTREQ			= 0x00000004,  /- 1 = User password not required -/
		ACB_TEMPDUP			= 0x00000008,  /- 1 = Temporary duplicate account -/
		ACB_NORMAL			= 0x00000010,  /- 1 = Normal user account -/
		ACB_MNS				= 0x00000020,  /- 1 = MNS logon user account -/
		ACB_DOMTRUST			= 0x00000040,  /- 1 = Interdomain trust account -/
		ACB_WSTRUST			= 0x00000080,  /- 1 = Workstation trust account -/
		ACB_SVRTRUST			= 0x00000100,  /- 1 = Server trust account -/
		ACB_PWNOEXP			= 0x00000200,  /- 1 = User password does not expire -/
		ACB_AUTOLOCK			= 0x00000400,  /- 1 = Account auto locked -/
		ACB_ENC_TXT_PWD_ALLOWED		= 0x00000800,  /- 1 = Encryped text password is allowed -/
		ACB_SMARTCARD_REQUIRED		= 0x00001000,  /- 1 = Smart Card required -/
		ACB_TRUSTED_FOR_DELEGATION	= 0x00002000,  /- 1 = Trusted for Delegation -/
		ACB_NOT_DELEGATED		= 0x00004000,  /- 1 = Not delegated -/
		ACB_USE_DES_KEY_ONLY		= 0x00008000,  /- 1 = Use DES key only -/
		ACB_DONT_REQUIRE_PREAUTH	= 0x00010000,  /- 1 = Preauth not required -/
		ACB_PW_EXPIRED                  = 0x00020000,  /- 1 = Password Expired -/
		ACB_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 0x00040000,
		ACB_NO_AUTH_DATA_REQD		= 0x00080000,  /- 1 = No authorization data required -/
		ACB_PARTIAL_SECRETS_ACCOUNT	= 0x00100000,
		ACB_USE_AES_KEYS		= 0x00200000
	} samr_AcctFlags;
	 * @throws IOException 

	**/
	private void updateUserAttributes(SamrService sam, UserHandle userHandle, Account account) throws IOException {
		if (account.getStatus() == AccountStatus.REMOVED)
			sam.deleteUser(userHandle);
		else {
			UserInfo ui = sam.queryUserInfo(userHandle);
			ui.setFullName(account.getDescription());
			final String description = (String) account.getAttributes().get("description");
			if (description != null)
				ui.setDescription(description);
			if (account.isDisabled())
				ui.setFlags(ui.getFlags() | 0x1); // Disabled
			else
				ui.setFlags(ui.getFlags() & 0xfffffffe); // Enabled
			if (account.getAttributes().get("gid") != null)
				ui.setPrimaryGid( Integer.parseInt( account.getAttributes().get("gid").toString() ));
			sam.setUserInfo(userHandle, ui);
		}
			
	}

	@Override
	public void updateUser(Account account) throws RemoteException, InternalErrorException {
		if (!onlyPassword)
			updateUser(account, null);
	}

	@Override
	public void removeUser(String userName) throws RemoteException, InternalErrorException {
		if (!onlyPassword) {
			Account acc = getServer().getAccountInfo(userName, getAgentName());
			if (acc == null) {
				acc = new Account();
				acc.setName(userName);
				acc.setDescription(userName);
				acc.setStatus(AccountStatus.REMOVED);
				acc.setDisabled(true);
			}
			updateUser(acc);
		}
	}

	@Override
	public void updateUserPassword(String userAccount, User userData, Password password, boolean mustchange)
			throws RemoteException, InternalErrorException {
		boolean found = false;
		try {
			Session session = getSession();
			try {
			    final RPCTransport transport2 = SMBTransportFactories.SAMSVC.getTransport(session);
			    log.info("OPEN SAM SERVICE");
			    SamrService sam = new SamrService(transport2, session);
			    ServerHandle serverHandle = sam.openServer();
			    MembershipWithName[] domains = sam.getDomainsForServer(serverHandle);
			    for (MembershipWithName n: domains)
			    {
				    SID sid = sam.getSIDForDomain(serverHandle, n.getName());
			    	DomainHandle domainHandle = sam.openDomain(serverHandle, sid);
			    	if (isDebug())
			    		log.info("Searching user "+userAccount+" at SAM domain "+n.getName());
			    	int [] r;
			    	try {
			    		r = sam.lookupNames(domainHandle, new String[] {userAccount});
			    	} catch (RPCException e) {
			    		if (e.getErrorCode() == SystemErrorCode.STATUS_NONE_MAPPED)
			    			continue;
			    		else
			    			throw e;
			    	}
			    	for (int i: r) {
			    		if (isDebug())
			    			log.info("Opening user "+userAccount+" at SAM domain "+n.getName());
			    		UserHandle userHandle = sam.openUser(domainHandle, i, 0x000F07FF);
			    		try {
			    			sam.setPassword(userHandle, password.getPassword(), mustchange);
			    			found = true;
			    		} finally {
			    			sam.closeHandle(userHandle);
			    		}
			    	}		    	
			    }
			} finally {
				closeSession(session);
			}
			if (!found)
				throw new InternalErrorException("Unable to find account "+userAccount);
		} catch (RPCException e) {
			throw new InternalErrorException("Error getting accounts list", e);
		} catch (IOException e) {
			throw new InternalErrorException("Error getting accounts list", e);
		}
	}

	@Override
	public boolean validateUserPassword(String userName, Password password)
			throws RemoteException, InternalErrorException {
		try {
			if (smbConnection != null && !smbConnection.isConnected()) {
				smbConnection.close(true);
				smbConnection = null;
			}
			if (smbConnection == null)
				smbConnection = smbClient.connect(server);
			final AuthenticationContext smbAuthenticationContext = new AuthenticationContext(
					userName, password.getPassword().toCharArray(), "");
//			log.info("Authenticating "+userName+" "+password.getPassword());
			try {
				final Session session = smbConnection.authenticate(smbAuthenticationContext);
				session.close();
				log.info("Authenticated user "+userName);
				return true;
			} catch (SMBApiException e) {
				if (e.getStatusCode() == 0xc0000224L || e.getStatusCode() == 0xc0000071L)
				{
					log.info("Password expired for "+userName);
					return true; //PasswordValidation.PASSWORD_GOOD_EXPIRED;
				}
				else if (e.getStatusCode() == 0xc000006dL) 
				{
					log.info("Password wrong for "+userName);					
					return false; // PasswordValidation.PASSWORD_WRONG;
				}
				else
					throw e;
			}
		} catch (IOException e) {
			throw new InternalErrorException("Error checking password for "+userName, e);
		}
	}
	
	public Session getSession() throws IOException, InternalErrorException {
		if (smbConnection != null && !smbConnection.isConnected()) {
			smbConnection.close(true);
			smbConnection = null;
		}
		if (smbConnection == null)
			smbConnection = smbClient.connect(server);
		
		try {
		    final AuthenticationContext smbAuthenticationContext = new AuthenticationContext(
		    		user, password.getPassword().toCharArray(), domain);
		    log.info("Authenticating");
		    final Session session = smbConnection.authenticate(smbAuthenticationContext);
		    return session;
		} catch (SMBApiException e) {
			if (e.getStatus() == NtStatus.STATUS_LOGON_FAILURE) {
				Password p;
				if (! domain.equalsIgnoreCase(server)) {
					Collection<Account> accounts = new RemoteServiceLocator()
							.getAccountService()
							.findAccountByJsonQuery(
									"(name eq \""
											+ user
											.replace("\\", "\\\\")
											.replace("\"", "\\\"")
											.replace("\'", "\\\'")
											+ "\" or name ew \"\\" 
											+ user
											.replace("\\", "\\\\")
											.replace("\"", "\\\"")
											.replace("\'", "\\\'")
											+ "\") " 
											+ "and type eq 'S' "
											+ "and system.className co 'ActiveDirectory' "
											+ "and secrets pr");
					for (Account account: accounts) {
						try {
							log.info("Fetching password for "+account.getName()+" at "+account.getSystem());
							p = getServer().getAccountPassword(account.getName(), account.getSystem());
							if (p != null) {
								final AuthenticationContext smbAuthenticationContext = new AuthenticationContext(
										user, p.getPassword().toCharArray(), domain);
								log.info("Authenticating");
								final Session session = smbConnection.authenticate(smbAuthenticationContext);
								password = p;
								return session;
							}
						} catch (Exception ex) {
							// Password is not valid
						}
					}
				}
				p = getServer().getAccountPassword(getAgentName(), user);
				if (p == null || p.getPassword().equals(password.getPassword()))
					throw e;
				final AuthenticationContext smbAuthenticationContext = new AuthenticationContext(
						user, p.getPassword().toCharArray(), domain);
				log.info("Authenticating");
				final Session session = smbConnection.authenticate(smbAuthenticationContext);
				password = p;
				return session;
				
			} else
				throw e;
		}

	}

	@Override
	public void configureMappings(Collection<ExtensibleObjectMapping> objects)
			throws RemoteException, InternalErrorException {
		
	}

	@Override
	public ExtensibleObject getNativeObject(SoffidObjectType type, String object1, String object2)
			throws RemoteException, InternalErrorException {
		return null;
	}

	@Override
	public ExtensibleObject getSoffidObject(SoffidObjectType type, String object1, String object2)
			throws RemoteException, InternalErrorException {
		return null;
	}

	public Collection<Map<String, Object>> invoke(String verb, String command,
			Map<String, Object> params) throws RemoteException, InternalErrorException 
	{
		Collection<Map<String, Object>> l = new LinkedList<Map<String, Object>>();
		if (verb.equals("hostname"))
		{
			Session session;
			try {
				session = getSession();
				try {
					String s = session.getConnection().getConnectionInfo().getNetBiosName();
					HashMap<String, Object> m = new HashMap<String,Object>();
					m.put("result", s.toLowerCase());
					l = new LinkedList<>();
					l.add(m);
				} finally {
					closeSession(session);
				}
			} catch (IOException e) {
				throw new InternalErrorException("Error querying host name", e);
			}
		}
		if (verb.equals("get-user-sid")) {
			String sid = getUserSid(command);
			if (sid != null) {
				HashMap<String,Object> m = new HashMap<>();
				m.put("sid", sid);
				l.add(m);
			}
		}
		if (verb.equals("add-group")) {
			String user = (String) params.get("user");
			String group = (String) params.get("group");
			try {
				String sid = getUserSid(user);
				if (sid != null) {
					Session session = getSession();
					try {
					    final RPCTransport transport2 = SMBTransportFactories.SAMSVC.getTransport(session);
					    SamrService sam = new SamrService(transport2, session);
					    addAliasMember(sam, SID.fromString(sid), group);
					} finally {
						closeSession(session);
					}
				}
				return null;
			} catch (RPCException e) {
				throw new InternalErrorException("Error getting accounts list", e);
			} catch (IOException e) {
				throw new InternalErrorException("Error getting accounts list", e);
			}
		}
		if (verb.equals("delete-group")) {
			String user = (String) params.get("user");
			String group = (String) params.get("group");
			try {
				String sid = getUserSid(user);
				if (sid != null) {
					Session session = getSession();
					try {
					    final RPCTransport transport2 = SMBTransportFactories.SAMSVC.getTransport(session);
					    SamrService sam = new SamrService(transport2, session);
					    deleteAliasMember(sam, SID.fromString(sid), group);
					} finally {
						closeSession(session);
					}
				}
				return null;
			} catch (RPCException e) {
				throw new InternalErrorException("Error getting accounts list", e);
			} catch (IOException e) {
				throw new InternalErrorException("Error getting accounts list", e);
			}
		}
		return l;
	}
	
	public String getUserSid(String userAccount) throws RemoteException, InternalErrorException {
		try {
			Session session = getSession();
			try {
			    final RPCTransport transport2 = SMBTransportFactories.SAMSVC.getTransport(session);
			    SamrService sam = new SamrService(transport2, session);
			    ServerHandle serverHandle = sam.openServer();
			    MembershipWithName[] domains = sam.getDomainsForServer(serverHandle);
			    for (MembershipWithName n: domains)
			    {
				    SID sid = sam.getSIDForDomain(serverHandle, n.getName());
			    	DomainHandle domainHandle = sam.openDomain(serverHandle, sid);
			    	if (isDebug())
			    		log.info("Searching user "+userAccount+" at SAM domain "+n.getName());
			    	int [] r;
			    	try {
			    		r = sam.lookupNames(domainHandle, new String[] {userAccount});
			    	} catch (RPCException e) {
			    		if (e.getErrorCode() == SystemErrorCode.STATUS_NONE_MAPPED)
			    			continue;
			    		else
			    			throw e;
			    	}
			    	for (int i: r) {
			    		return sid.resolveRelativeID(i).toString();
			    	}		    	
			    }
			} finally {
				closeSession(session);
			}
			return null;
		} catch (RPCException e) {
			throw new InternalErrorException("Error getting accounts list", e);
		} catch (IOException e) {
			throw new InternalErrorException("Error getting accounts list", e);
		}
	}

}
