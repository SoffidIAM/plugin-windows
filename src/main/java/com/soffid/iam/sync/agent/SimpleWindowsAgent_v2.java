package com.soffid.iam.sync.agent;

import java.io.IOException;
import java.rmi.RemoteException;
import java.util.LinkedList;
import java.util.List;

import com.hierynomus.smbj.session.Session;
import com.rapid7.client.dcerpc.RPCException;
import com.rapid7.client.dcerpc.msvcctl.dto.IServiceConfigInfo;
import com.rapid7.client.dcerpc.msvcctl.dto.ServiceConfigInfo;
import com.rapid7.client.dcerpc.msvcctl.dto.ServiceHandle;
import com.rapid7.client.dcerpc.msvcctl.dto.ServiceManagerHandle;
import com.rapid7.client.dcerpc.msvcctl.dto.enums.ServiceError;
import com.rapid7.client.dcerpc.msvcctl.dto.enums.ServiceStartType;
import com.rapid7.client.dcerpc.msvcctl.dto.enums.ServiceState;
import com.rapid7.client.dcerpc.msvcctl.dto.enums.ServiceType;
import com.rapid7.client.dcerpc.transport.RPCTransport;
import com.rapid7.client.dcerpc.transport.SMBTransportFactories;
import com.soffid.iam.api.Account;
import com.soffid.iam.api.HostService;
import com.soffid.iam.api.Password;
import com.soffid.iam.sync.intf.ServiceMgr;
import com.soffid.msrpc.svcctl.EnumServiceStatus;
import com.soffid.msrpc.svcctl.ServiceControlManagerService;

import es.caib.seycon.ng.exception.InternalErrorException;

public class SimpleWindowsAgent_v2 extends SimpleWindowsAgent implements ServiceMgr {

	@Override
	public List<HostService> getHostServices() throws RemoteException, InternalErrorException {
		try {
			Session session = getSession();
			List<HostService> services = new LinkedList<>();
			try {
			    final RPCTransport transport2 = SMBTransportFactories.SVCCTL.getTransport(session);
			    ServiceControlManagerService svc = new ServiceControlManagerService(transport2, session);
			    ServiceManagerHandle smh = svc.openServiceManagerHandle();
			    
			    List<EnumServiceStatus> s = svc.enumServicesStatus(smh, ServiceType.WIN32_OWN_PROCESS.getValue()+
			    			ServiceType.WIN32_SHARE_PROCESS.getValue(), ServiceState.STATE_ALL);
			    for (EnumServiceStatus service: s) {
			    	try {
			    		ServiceHandle h = svc.openServiceHandle(smh, service.getServiceName());
				    	IServiceConfigInfo config = svc.queryServiceConfig(h);
				    	svc.closeServiceHandle(h);
				    	HostService hostService = new HostService();
				    	hostService.setHostName(server);
				    	hostService.setService(service.getServiceName());
				    	hostService.setAccountName(config.getServiceStartName());
						services.add(hostService);
			    	} catch (RPCException e) {
			    		
			    	} 
			    }
			    return services;
			} finally {
				session.close();
			}
		} catch (IOException e) {
			throw new InternalErrorException("Error fetching services", e);
		}
	}

	@Override
	public void setServicePassword(String service, Account account, Password password)
			throws RemoteException, InternalErrorException {
		try {
			Session session = getSession();
			List<HostService> services = new LinkedList<>();
			try {
			    final RPCTransport transport2 = SMBTransportFactories.SVCCTL.getTransport(session);
			    ServiceControlManagerService svc = new ServiceControlManagerService(transport2, session);
			    ServiceManagerHandle smh = svc.openServiceManagerHandle();

			    ServiceHandle h = svc.openServiceHandle(smh, service);
			    IServiceConfigInfo config = svc.queryServiceConfig(h);
			    ServiceConfigInfo config2 = new ServiceConfigInfo(
			    		ServiceType.NO_CHANGE,
			    		ServiceStartType.NO_CHANGE,
			    		ServiceError.NO_CHANGE,
			    		null, 
			    		null,
			    		0,
			    		null, // config.getDependencies(),
			    		config.getServiceStartName(),
			    		null,
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
}
