package com.soffid.iam.sync.agent;

import java.io.IOException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPControl;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPReferralException;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.LDAPSearchResults;
import com.novell.ldap.controls.LDAPPagedResultsControl;
import com.novell.ldap.controls.LDAPPagedResultsResponse;
import com.soffid.iam.remote.RemoteServiceLocator;

import es.caib.seycon.ng.comu.Dispatcher;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.sync.intf.AuthoritativeChange;
import es.caib.seycon.ng.sync.intf.ExtensibleObject;
import es.caib.seycon.ng.sync.intf.ExtensibleObjectMapping;
import es.caib.seycon.ng.sync.intf.ExtensibleObjects;
import es.caib.seycon.ng.utils.Security;

public class RealTimeChangeLoader implements Runnable {
	Log log = LogFactory.getLog(getClass());
	
	String agentName;
	LDAPPool pool;
	String baseDn;
	boolean debugEnabled;

	private CustomizableActiveDirectoryAgent agent;

	private ExtensibleObjectMapping mapping;

	private String tenant;
	
	private Dispatcher dispatcher;
	
	public LDAPPool getPool() {
		return pool;
	}
	public void setPool(LDAPPool pool) {
		this.pool = pool;
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
		LDAPSearchResults query = null;
		LDAPConnection  conn = null;
		try {
			Security.nestedLogin(tenant, agentName, Security.ALL_PERMISSIONS);
			conn = pool.getConnection();
			LDAPConstraints constraints = conn.getConstraints();
			
			LDAPPagedResultsControl pageResult = new LDAPPagedResultsControl(
					conn.getSearchConstraints().getMaxResults(),
					false);


			LDAPSearchConstraints ldsc = new LDAPSearchConstraints(constraints);
			ldsc.setReferralFollowing(true);
			ldsc.setDereference(ldsc.DEREF_NEVER);
			ldsc.setHopLimit(10);
			ldsc.setControls( 
					new LDAPControl [] {
						new LDAPControl ("1.2.840.113556.1.4.528", true, null),
						pageResult
					});
			
			log.info("Searching changes in "+baseDn);
			query = conn.search(baseDn, LDAPConnection.SCOPE_SUB, "(objectClass=*)", null,
					false, ldsc);
			do
			{
				while (query.hasMore()) {
					try {
						LDAPEntry entry = query.next();
						if (Thread.interrupted())
							return;
						String dn = entry.getDN();
						log.info("Received change from "+dn);
						process (entry);
					} catch (LDAPReferralException e) {
						log.warn("Error following referral "+e.getFailedReferral(), e);
					}
				}
				LDAPControl responseControls[] = query.getResponseControls();
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
		} catch (InterruptedException e) {
			log.info("Stopped");
		} catch (Exception e) {
			log.warn("Error retrieving changes", e);
		} finally {
			log.info("Returning connection");
			if (query != null)
			{
				try {
					conn.abandon(query);
				} catch (Throwable e) {
				}
			}
			pool.returnConnection();
//			pool.diagConnection(LoggerFactory.getLogger(getClass()));
//			pool.diag(LoggerFactory.getLogger(getClass()));
		}
	}
		
	private void process(LDAPEntry entry) throws InternalErrorException, IOException {
		try {
			if (dispatcher.isAuthoritative())
			{
				LDAPAttribute att = entry.getAttribute("objectClass");
				ExtensibleObject ldapObject = agent.parseEntry(entry, mapping);
				ExtensibleObjects parsedObjects = agent.getObjectTranslator()
						.parseInputObjects(ldapObject);
				for (ExtensibleObject object : parsedObjects.getObjects()) {
					if (debugEnabled)
					{
						agent.debugObject("Got Soffid object", object, "  ");
					}
					AuthoritativeChange change = null;
					
					if (isUser(entry))
						change = agent.parseUserChange(object);
					if (change == null)
						change = agent.parseGroupChange(object);
					if (change == null)
						change = agent.parseCustomObjectChange(object);
					if (change != null)
					{
						boolean ignore = false;
						if (entry.getDN().contains("\\0ADEL:") && entry.getDN().contains("CN=Deleted Objects"))
						{
							if (change.getUser() != null)
								change.getUser().setActiu(false);
							if (change.getGroup() != null)
								change.getGroup().setObsolet(true);
							if (change.getObject() != null)
							{
								new RemoteServiceLocator().getCustomObjectService().deleteCustomObject(change.getObject());
								ignore = true;
							}
						}
						if ( ! ignore)
						{
							boolean remove = entry.getAttribute("isDeleted") != null && 
									"TRUE".equals(entry.getAttribute("isDeleted").getStringValue());
							new es.caib.seycon.ng.remote.RemoteServiceLocator().getServerService().processAuthoritativeChange(change, remove);
						}
					}
				}
			} else {
				if (entry.getDN().contains("\\0ADEL:") && entry.getDN().contains("CN=Deleted Objects"))
				{
					// Account deleted
				}
				else if ( isUser(entry))
				{
					String accountName = null;
					for (ExtensibleObjectMapping mapping : agent.objectMappings) {
						if (mapping.getSoffidObject().equals( es.caib.seycon.ng.comu.SoffidObjectType.OBJECT_ACCOUNT )) {
							accountName = agent.generateAccountName(entry, mapping, "accountName");
						}
					}
					log.info("Reconcile account name = "+accountName);
					if ( accountName != null)
					{
						new es.caib.seycon.ng.remote.RemoteServiceLocator().getServerService().reconcileAccount(dispatcher.getCodi(), accountName);
					}
				}
			}
		} catch (Exception e) {
			log.warn("Error processing authortative change", e);
		}

	}
	
	private boolean isUser(LDAPEntry entry) {
		LDAPAttribute accountAttribute = entry.getAttribute("sAMAccountName");
		if (accountAttribute == null)
			return false;
		boolean user = false;
		boolean computer = false;
		for (String v: entry.getAttribute("objectClass").getStringValueArray())
		{
			if (v.equalsIgnoreCase("user"))
				user = true;
			if (v.equalsIgnoreCase("computer"))
				computer = true;
		}
		return user && !computer;
	}
	public void setAgent(CustomizableActiveDirectoryAgent customizableActiveDirectoryAgent) {
		agent = customizableActiveDirectoryAgent;
	}
	public void setMaping(ExtensibleObjectMapping m) 
	{
		mapping = m;
	}
	public void setTenant(String tenant) {
		this.tenant = tenant;
		
	}
	public Dispatcher getDispatcher() {
		return dispatcher;
	}
	public void setDispatcher(Dispatcher dispatcher) {
		this.dispatcher = dispatcher;
	}
}
