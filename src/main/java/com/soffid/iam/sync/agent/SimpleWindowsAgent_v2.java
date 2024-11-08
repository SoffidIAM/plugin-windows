package com.soffid.iam.sync.agent;

import java.io.IOException;
import java.net.ConnectException;
import java.net.NoRouteToHostException;
import java.rmi.RemoteException;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.apache.cxf.interceptor.Fault;
import org.json.JSONException;
import org.json.JSONObject;

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
import com.soffid.iam.pwsh.PowershellException;
import com.soffid.iam.sync.intf.ServiceMgr;
import com.soffid.msrpc.svcctl.EnumServiceStatus;
import com.soffid.msrpc.svcctl.ServiceControlManagerService;

import es.caib.seycon.ng.exception.InternalErrorException;

public class SimpleWindowsAgent_v2 extends SimpleWindowsAgent implements ServiceMgr {

	@Override
	public List<HostService> getHostServices() throws RemoteException, InternalErrorException {
		try {
			String powerShellAgent = getServer().getConfig("soffid.discovery.powershell");
			if ("false".equals(powerShellAgent)) {
				return getNativeServices();
			} else {
				try {
					return getPowerShellServices(powerShellAgent);
				} catch (Fault | IllegalStateException f) {
					if (f instanceof IllegalStateException ||
							f.getCause() instanceof ConnectException ||
							f.getCause() instanceof NoRouteToHostException) {
						return getNativeServices();
					}
					else
						throw f;
				}
			}
		} catch (Exception e) {
			throw new InternalErrorException("Error fetching services", e);
		}
	}

	protected List<HostService> getNativeServices() throws IOException, InternalErrorException {
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
	}

	private List<HostService> getPowerShellServices(String powerShellAgent) throws InternalErrorException, JSONException, PowershellException {
		com.soffid.iam.pwsh.Session s;
		String defaultDomain = null;
		try { 
			log.info("Connecting to "+server+" with "+user+" / "+password.toString());
			s = new com.soffid.iam.pwsh.Session(
					server, user, password.getPassword());
			List<JSONObject> r = s.powershell("[System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain() | select-object Name");
			log.info("Result="+r);
			for (JSONObject rr: r) {
				defaultDomain = rr.optString("Name", null);
				log.info("Domain="+defaultDomain);
			}
		} catch (Exception e) {
			String userName = domain.equals(server) ? user: domain+"\\"+user; 
			log.info("Connecting to "+server+" with "+userName+" / "+password.toString());
			s = new com.soffid.iam.pwsh.Session(
					server, userName, password.getPassword());
		}
		List<HostService> services = new LinkedList<>();
		// Services
		for (JSONObject row:  s.powershell( 
				"get-wmiobject Win32_Service | select-object Name,StartName")) {
			String runas = (String) row.get("StartName");
			if (runas != null &&
				      ! "SYSTEM".equalsIgnoreCase(runas) && 
			      ! "LocalSystem".equalsIgnoreCase(runas) &&
			      ! "NT AUTHORITY\\NetworkService".equalsIgnoreCase(runas) &&
			      ! "NT AUTHORITY\\LocalService".equalsIgnoreCase(runas) &&
			      ! "".equals(runas) && runas != null &&
			      ! runas.endsWith("$")) {
				HostService hs = new HostService();
				if (!runas.contains("@") && !runas.contains("\\") && defaultDomain != null)
					runas = defaultDomain.toLowerCase()+"\\"+runas;
				hs.setAccountName(runas);
				hs.setService((String) row.get("Name"));
				hs.setHostName(server);
				services.add(hs);
			}
		}
		// Scheduled tasks
		for (JSONObject row:  s.powershell( 
				"get-scheduledTask | select-object TaskPath, TaskName,@{name='runas';expression={$_.Principal.UserId}}")) {
			String runas = (String) row.get("runas");
			if (runas != null &&
				      ! "SYSTEM".equalsIgnoreCase(runas) && 
			      ! "LocalSystem".equalsIgnoreCase(runas) &&
			      ! "NT AUTHORITY\\NetworkService".equalsIgnoreCase(runas) &&
			      ! "NT AUTHORITY\\LocalService".equalsIgnoreCase(runas) &&
			      ! "".equals(runas) && runas != null &&
			      ! runas.endsWith("$")) {
				HostService hs = new HostService();
				if (!runas.contains("@") && !runas.contains("\\") && defaultDomain != null)
					runas = defaultDomain.toLowerCase()+"\\"+runas;
				hs.setAccountName(runas);
				hs.setService("TASK: "+(String) row.get("TaskPath")+row.get("TaskName"));
				hs.setHostName(server);
				services.add(hs);
			}
		}
		// IIS
		for (JSONObject row:  getIISApplications(s)) {
			String runas = (String) row.optString("userName");
			if (runas != null && ! runas.isBlank()) {
				HostService hs = new HostService();
				if (!runas.contains("@") && !runas.contains("\\") && defaultDomain != null)
					runas = defaultDomain.toLowerCase()+"\\"+runas;
				hs.setAccountName(runas);
				hs.setService("IIS: "+(String) row.get("name"));
				hs.setHostName(server);
				services.add(hs);
			}
		}
		return services;
	}

	private String quote(String t) {
		return t.replace("'", "''");
	}

	@Override
	public void setServicePassword(String service, Account account, Password password)
			throws RemoteException, InternalErrorException {
		try {
			String powerShellAgent = getServer().getConfig("soffid.discovery.powershell");
			if ("false".equals(powerShellAgent)) {
				setNativeServicePassword(service, password);
			} else {
				setPowershellServicePassword(service, password);
			}
		} catch (Exception e) {
			throw new InternalErrorException("Error fetching services", e);
		}
	}

	private void setPowershellServicePassword(String service, Password password) throws JSONException, PowershellException {
		com.soffid.iam.pwsh.Session s = new com.soffid.iam.pwsh.Session(
				server, user, this.password.getPassword());
		// Services
		for (JSONObject row:  s.powershell( 
				"get-wmiobject Win32_Service | select-object Name,StartName")) {
			String runas = (String) row.get("StartName");
			String name = row.getString("Name");
			if ( name.equals(service) && 
				  runas != null &&
				  ! "SYSTEM".equalsIgnoreCase(runas) && 
			      ! "LocalSystem".equalsIgnoreCase(runas) &&
			      ! "NT AUTHORITY\\NetworkService".equalsIgnoreCase(runas) &&
			      ! "NT AUTHORITY\\LocalService".equalsIgnoreCase(runas) &&
			      ! "".equals(runas) && runas != null &&
			      ! runas.endsWith("$")) {
				s.powershell("Get-WMIObject -class Win32_Service -Filter 'Name=''"+quoteWmiQuery(name)+"''' | "+
						"foreach { $_.change($null,$null,$null,$null,$null,$null,$null,'"+password.getPassword().replace("'","''")+"')}");
			}
		}
		// Scheduled tasks
		for (JSONObject row:  s.powershell( 
				"get-scheduledTask | select-object TaskPath, TaskName,@{name='runas';expression={$_.Principal.UserId}}")) {
			String runas = (String) row.get("runas");
			String name = "TASK: "+(String) row.get("TaskPath")+row.get("TaskName");
			if (name.equals(service) &&
				runas != null &&
				  ! "SYSTEM".equalsIgnoreCase(runas) && 
			      ! "LocalSystem".equalsIgnoreCase(runas) &&
			      ! "NT AUTHORITY\\NetworkService".equalsIgnoreCase(runas) &&
			      ! "NT AUTHORITY\\LocalService".equalsIgnoreCase(runas) &&
			      ! "".equals(runas) && runas != null &&
			      ! runas.endsWith("$")) {
				s.powershell("set-scheduledTask -TaskName '"+
						quote(row.getString("TaskName"))+"' -TaskPath '"+
						quote(row.getString("TaskPath"))+"' -User '"+quote(runas)+"' "
						+ "-Password '"+quote(password.getPassword())+"'");
			}
		}
		// IIS
		for (JSONObject row:  getIISApplications(s)) {
			String name = "IIS: "+(String) row.optString("name");
			if (service.equals(name)) {
				s.powershell("import-module webadministration; "
					+ "set-itemproperty -path 'IIS:\\AppPools\\"+quote(name.substring(5))+"' "
					+ "-name processModel.password "
					+ "-value '"+quote(password.getPassword())+"'");
			}
		}
	}

	protected List<JSONObject> getIISApplications(com.soffid.iam.pwsh.Session s) throws PowershellException {
		try {
			return s.powershell( 
				"import-module webadministration; get-childitem -path IIS:\\AppPools\\ | select-object name,@{e={$_.processModel.userName};l=\"userName\"}");
		} catch (Exception e) {
			return new LinkedList<>();
		}
	}

	private String quoteWmiQuery(String name) {
		return name.replace("\\", "\\\\")
				.replace("'", "\\''")
				.replace("\"", "\\\"");
	}

	protected void setNativeServicePassword(String service, Password password)
			throws IOException, InternalErrorException {
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
	}
}
