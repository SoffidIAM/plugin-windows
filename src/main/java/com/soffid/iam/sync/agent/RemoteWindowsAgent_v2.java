package com.soffid.iam.sync.agent;

import java.io.IOException;
import java.rmi.RemoteException;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;

import com.soffid.iam.api.Account;
import com.soffid.iam.api.HostService;
import com.soffid.iam.api.Password;
import com.soffid.iam.sync.intf.ServiceMgr;
import com.soffid.iam.sync.nas.NASManager;

import es.caib.seycon.ng.exception.InternalErrorException;

public class RemoteWindowsAgent_v2 extends RemoteWindowsAgent implements ServiceMgr {
	public RemoteWindowsAgent_v2() throws RemoteException {
		super();
	}

	@Override
	public List<HostService> getHostServices() throws RemoteException, InternalErrorException {
		try {
			NASManager nasManager = new NASManager(serverName, serverName, userName, password, new HashMap<>(),
					isDebug());
			List<String> servers = new LinkedList<>();
			servers.add(serverName);
			return nasManager.getHostServices(servers);
		} catch (IOException e) {
			throw new InternalErrorException("Error fetching services", e);
		}
	}

	@Override
	public void setServicePassword(String service, Account account, Password password)
			throws RemoteException, InternalErrorException {
		try {
			NASManager nasManager = new NASManager(serverName, serverName, userName, this.password, new HashMap<>(),
					isDebug());
			nasManager.setServicePassword(Collections.singletonList(serverName), service, password);
		} catch (IOException e) {
			throw new InternalErrorException("Error fetching services", e);
		}
	}


}
