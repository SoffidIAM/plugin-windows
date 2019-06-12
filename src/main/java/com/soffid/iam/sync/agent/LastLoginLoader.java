package com.soffid.iam.sync.agent;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPControl;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPReferralException;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.LDAPSearchResults;
import com.novell.ldap.controls.LDAPPagedResultsControl;
import com.novell.ldap.controls.LDAPPagedResultsResponse;
import com.soffid.iam.ServiceLocator;
import com.soffid.iam.api.Account;
import com.soffid.iam.api.Configuration;
import com.soffid.iam.config.Config;
import com.soffid.iam.remote.RemoteServiceLocator;
import com.soffid.iam.service.AccountService;
import com.soffid.iam.service.ConfigurationService;
import com.soffid.iam.sync.service.ServerService;

import es.caib.seycon.ng.sync.intf.ExtensibleObjectMapping;
import es.caib.seycon.ng.utils.Security;

public class LastLoginLoader implements Runnable {
	Log log = LogFactory.getLog(getClass());
	
	String agentName;
	LDAPPool pool;
	String domainController;
	String baseDn;
	boolean debugEnabled;

	private CustomizableActiveDirectoryAgent agent;

	private ExtensibleObjectMapping mapping;

	private String tenant;
	
	public LDAPPool getPool() {
		return pool;
	}
	public void setPool(LDAPPool pool) {
		this.pool = pool;
	}
	public String getDomainController() {
		return domainController;
	}
	public void setDomainController(String domainController) {
		this.domainController = domainController;
	}
	
	
	public String getAgentName() {
		return agentName;
	}
	public void setAgentName(String agentName) {
		this.agentName = agentName;
	}
	public String getBaseDn() {
		return baseDn;
	}
	public void setBaseDn(String baseDn) {
		this.baseDn = baseDn;
	}
	
	public boolean isDebugEnabled() {
		return debugEnabled;
	}
	public void setDebugEnabled(boolean debugEnabled) {
		this.debugEnabled = debugEnabled;
	}
	
	public void run() {
		try {
			Security.nestedLogin(tenant, agentName, Security.ALL_PERMISSIONS);
			LDAPConnection conn = pool.getConnection();
			Config config = Config.getConfig();
			if (!config.isServer())
				return;
			
			
			AccountService accountService = ServiceLocator.instance().getAccountService() ;
			ConfigurationService configService = ServiceLocator.instance().getConfigurationService();

			String paramName = "soffid.lastLogin."+domainController;
			Configuration cfg = configService.findParameterByNameAndNetworkName(paramName, null);
			String lastLoad = "1";
			if (cfg != null && cfg.getValue() != null)
				lastLoad = cfg.getValue();
			DateFormat dateFormat = SimpleDateFormat.getDateTimeInstance(SimpleDateFormat.SHORT, SimpleDateFormat.SHORT);
			long start = System.currentTimeMillis();
			String query;
			query = "(&(objectClass=user)(!(objectClass=computer))(lastLogon>="+lastLoad+"))";
			LDAPPagedResultsControl pageResult = new LDAPPagedResultsControl(
								conn.getSearchConstraints().getMaxResults(),
								false);

			do {
				LDAPSearchConstraints constraints = new LDAPSearchConstraints(conn.getSearchConstraints());
				constraints.setControls(pageResult);
				log.info("Looking for last logon in "+ domainController +" LDAP QUERY="
										+ query + " on " + baseDn);
				LDAPSearchResults search = conn.search(baseDn,
						LDAPConnection.SCOPE_SUB, query,
						new String[] {"sAMAccountName","lastLogon"}, false, constraints);
				while (search.hasMore()) {
					try {
						LDAPEntry entry = search.next();
						String accountName = agent.generateAccountName(entry, mapping, "accountName");
						LDAPAttribute att = entry.getAttribute("lastLogon");
						if ( att != null)
						{
							Date d = lastLogonToDate(att.getStringValue());
							if (d != null)
							{
								Account acc = accountService.findAccount(accountName, agentName);
								if ( acc != null && (acc.getLastLogin() == null || d.after(acc.getLastLogin().getTime())))
								{
									Calendar c = Calendar.getInstance();
									c.setTime(d);
									acc.setLastLogin(c);
									if (debugEnabled) {
										log.info("Account "+accountName+" last logon on server "+domainController+" = "+dateFormat.format(c.getTime()));
									}
									accountService.updateAccount(acc);
								}
							}
						}
					} catch (LDAPReferralException e) {
					} catch (LDAPException e) {
						if (e.getResultCode() == LDAPException.NO_SUCH_OBJECT) {
							// Ignore
						} else {
							log.debug("LDAP Exception: "+e.toString());
							log.debug("ERROR MESSAGE: "+e.getLDAPErrorMessage());
							log.debug("LOCALIZED MESSAGE: "+e.getLocalizedMessage());
							throw e;
						}
					}
				}

				LDAPControl responseControls[] = search
						.getResponseControls();
				pageResult.setCookie(null); // in case no cookie is
											// returned we need
											// to step out of
											// do..while

				if (responseControls != null) {
					for (int i = 0; i < responseControls.length; i++) {
						if (responseControls[i] instanceof LDAPPagedResultsResponse) {
							LDAPPagedResultsResponse response = (LDAPPagedResultsResponse) responseControls[i];
							pageResult.setCookie(response
									.getCookie());
						}
					}
				}
			} while (pageResult.getCookie() != null);

			Date next = new Date ( start - 300000); // 5 minutes clock skew allowed
			if (cfg == null)
			{
				cfg = new Configuration();
				cfg.setCode(paramName);
				cfg.setValue(dateToLastLogon(next));
				configService.create(cfg);
			}
			else
			{
				cfg.setValue(dateToLastLogon(next));
				configService.update(cfg);
			}
		} catch (Exception e) {
			log.warn("Error retrieving last logon attributes for domain controller "+domainController, e);
		} finally {
			pool.returnConnection();
		}
	}
		
	public Date lastLogonToDate (String lastLogon)
	{
		if (lastLogon == null || lastLogon.trim().isEmpty())
			return null;
		long v = Long.decode(lastLogon);
		v = v / 10000000L;
		v -= 11644473600L;
		if ( v <= 0)
			return null;
		return new Date(v*1000);
	}

	public String dateToLastLogon (Date d)
	{
		long v = d.getTime();
		v += 11644473600000L;
		v = v * 10000L;
		return Long.toString(v);
	}
	public void setAgent(CustomizableActiveDirectoryAgent customizableActiveDirectoryAgent) {
		agent = customizableActiveDirectoryAgent;
	}
	public void setMaping(ExtensibleObjectMapping m) {
		mapping = m;
		
	}
	public void setTenant(String tenant) {
		this.tenant = tenant;
		
	}
}
