package com.soffid.iam.sync.agent2;

import java.io.IOException;
import java.rmi.RemoteException;
import java.util.LinkedList;
import java.util.List;

import com.soffid.iam.api.Account;
import com.soffid.iam.api.HostService;
import com.soffid.iam.api.Password;
import com.soffid.iam.sync.agent.LDAPPool;
import com.soffid.iam.sync.intf.ServiceMgr;

import es.caib.seycon.ng.exception.InternalErrorException;

public class CustomizableActiveDirectoryAgent_v2 extends CustomizableActiveDirectoryAgent 
	implements ServiceMgr{

	public CustomizableActiveDirectoryAgent_v2() throws RemoteException {
		super();
	}

	public List<HostService> getHostServices() throws RemoteException, InternalErrorException {
		List<String> domainControllers = new LinkedList<>();
		for ( String domainName: this.domainToShortName.keySet()) {
			LDAPPool pool = getPool(domainName);
			if (pool.getChildPools() == null || pool.getChildPools().isEmpty())
				createChildPools(pool);
			for (LDAPPool child: pool.getChildPools()) {
				domainControllers.add(child.getLdapHost());
			}
		}
		try {
			return nasManager.getHostServices(domainControllers);
		} catch (IOException e) {
			throw new InternalErrorException("Error fetching services", e);
		}
	}

	@Override
	public void setServicePassword(String service, Account account, Password password)
			throws RemoteException, InternalErrorException {
		List<String> domainControllers = new LinkedList<>();
		for ( String domainName: this.domainToShortName.keySet()) {
			LDAPPool pool = getPool(domainName);
			if (pool.getChildPools() == null || pool.getChildPools().isEmpty())
				createChildPools(pool);
			for (LDAPPool child: pool.getChildPools()) {
				domainControllers.add(child.getLdapHost());
			}
		}
		nasManager.setServicePassword(domainControllers, service, password);
	}

}
