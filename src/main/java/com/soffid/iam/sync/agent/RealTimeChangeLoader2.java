package com.soffid.iam.sync.agent;

import java.io.IOException;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPControl;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPReferralException;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.LDAPSearchResults;
import com.novell.ldap.controls.LDAPPagedResultsControl;
import com.novell.ldap.controls.LDAPPagedResultsResponse;
import com.soffid.iam.ServiceLocator;
import com.soffid.iam.api.Configuration;
import com.soffid.iam.config.Config;
import com.soffid.iam.remote.RemoteServiceLocator;
import com.soffid.iam.service.AccountService;
import com.soffid.iam.service.ConfigurationService;

import es.caib.seycon.ng.comu.Dispatcher;
import es.caib.seycon.ng.comu.Usuari;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownUserException;
import es.caib.seycon.ng.sync.intf.AuthoritativeChange;
import es.caib.seycon.ng.sync.intf.ExtensibleObject;
import es.caib.seycon.ng.sync.intf.ExtensibleObjectMapping;
import es.caib.seycon.ng.sync.intf.ExtensibleObjects;
import es.caib.seycon.ng.utils.Security;

public class RealTimeChangeLoader2 implements Runnable {
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

	SimpleDateFormat df = new SimpleDateFormat("yyyyMMddHHmmss");

	private Dispatcher dispatcher;
	
	public void run() {
		try {
			if (debugEnabled)
				log.info("Starting real time loader for " + domainController);
			Security.nestedLogin(tenant, agentName, Security.ALL_PERMISSIONS);
			LDAPConnection conn = pool.getConnection();
			Config config = Config.getConfig();
			if (!config.isServer())
				return;

			AccountService accountService = ServiceLocator.instance().getAccountService();
			ConfigurationService configService = ServiceLocator.instance().getConfigurationService();

			String paramName = "soffid.lastChange." + domainController;
			Configuration cfg = configService.findParameterByNameAndNetworkName(paramName, null);
			String lastLoad = "0";
			if (cfg != null && cfg.getValue() != null)
				lastLoad = cfg.getValue();
			else
				lastLoad = generateDummyUpdate(conn);
			DateFormat dateFormat = SimpleDateFormat.getDateTimeInstance(SimpleDateFormat.SHORT,
					SimpleDateFormat.SHORT);
			long start = System.currentTimeMillis();
			String query;
			query = "(&(usnChanged>=" + lastLoad + ")(objectClass=user)(!(objectClass=computer)))";
			LDAPPagedResultsControl pageResult = new LDAPPagedResultsControl(
					conn.getSearchConstraints().getMaxResults(), false);
			
			LDAPControl deletedObjects = new LDAPControl ("1.2.840.113556.1.4.417", true, null);

			try {
				do {
					LDAPSearchConstraints constraints = new LDAPSearchConstraints(conn.getSearchConstraints());
					constraints.setControls(new LDAPControl[] { deletedObjects, pageResult} );
					if (debugEnabled)
						log.info("Looking for changes in " + domainController + " LDAP QUERY=" + query + " on " + baseDn);
					LDAPSearchResults search = conn.search(baseDn, LDAPConnection.SCOPE_SUB, query,
							null, false, constraints);
					while (search.hasMore()) {
						try {
							LDAPEntry entry = search.next();
							process(entry);
							String ll = entry.getAttribute("usnChanged").getStringValue();
							if (ll != null && Integer.parseInt(ll) >= Integer.parseInt(lastLoad))
								lastLoad = Integer.toString(Integer.parseInt(ll)+1);
						} catch (LDAPReferralException e) {
							// Ignore
						} catch (LDAPException e) {
							if (e.getResultCode() == LDAPException.NO_SUCH_OBJECT) {
								// Ignore
							} else {
								log.debug("LDAP Exception: " + e.toString());
								log.debug("ERROR MESSAGE: " + e.getLDAPErrorMessage());
								log.debug("LOCALIZED MESSAGE: " + e.getLocalizedMessage());
								throw e;
							}
						}
					}
	
					LDAPControl responseControls[] = search.getResponseControls();
					pageResult.setCookie(null); // in case no cookie is
												// returned we need
												// to step out of
												// do..while
	
					if (responseControls != null) {
						for (int i = 0; i < responseControls.length; i++) {
							if (responseControls[i] instanceof LDAPPagedResultsResponse) {
								LDAPPagedResultsResponse response = (LDAPPagedResultsResponse) responseControls[i];
								pageResult.setCookie(response.getCookie());
							}
						}
					}
				} while (pageResult.getCookie() != null);
	
				if (cfg == null) {
					cfg = new Configuration();
					cfg.setCode(paramName);
					cfg.setValue(lastLoad);
					cfg.setDescription("Finished on "+ new Date().toString());
					configService.create(cfg);
				} else {
					cfg.setValue(lastLoad);
					cfg.setDescription("Finished on "+ new Date().toString());
					configService.update(cfg);
				}
			} catch (Exception e) {
				if (cfg == null) {
					cfg = new Configuration();
					cfg.setCode(paramName);
					cfg.setValue(lastLoad);
					cfg.setDescription("** Not finished yet **");
					configService.create(cfg);
				} else if ("** Not finished yet **".equals(cfg.getDescription())) {
					cfg.setValue(lastLoad);
					configService.update(cfg);
				}
				log.warn("Error retrieving last logon attributes for domain controller " + domainController, e);
			}
		} catch (Exception e) {
			log.warn("Error retrieving last logon attributes for domain controller " + domainController, e);
		} finally {
			pool.returnConnection();
		}
	}

	private String generateDummyUpdate(LDAPConnection conn) {
		try {
			String dn = agent.getAdministratorDN();
			if (dn == null) 
				return "0";
			LDAPEntry entry = conn.read(dn);
			if (entry == null)
				return "0";
			LDAPAttribute description = entry.getAttribute("description");
			if (description == null)
				conn.modify(dn, new LDAPModification(LDAPModification.ADD, new LDAPAttribute("description", domainController)));
			else
				conn.modify(dn, new LDAPModification(LDAPModification.REPLACE, new LDAPAttribute("description", domainController)));
			
			LDAPEntry entry2 = conn.read(dn);
			if (description == null)
				conn.modify(dn, new LDAPModification(LDAPModification.DELETE, entry2.getAttribute("description")));
			else
				conn.modify(dn, new LDAPModification(LDAPModification.REPLACE, description));
			return entry2.getAttribute("usnChanged").getStringValue();
		} catch (LDAPException e) {
			// Ignore
			return "0";
		}
	}

	public Date lastChangeToDate(String lastChange) throws ParseException {
		if (lastChange == null || lastChange.trim().isEmpty())
			return null;
		if (lastChange.contains("."))
			lastChange = lastChange.substring(0, lastChange.indexOf("."));
		df.setTimeZone(TimeZone.getTimeZone("UTC"));
		return df.parse(lastChange);
	}

	public String dateToLastLogon(Date d) {
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

	private void process(LDAPEntry entry) throws InternalErrorException, IOException {
		try {
			if (dispatcher.isAuthoritative()) {
				LDAPAttribute att = entry.getAttribute("objectClass");
				ExtensibleObject ldapObject = agent.parseEntry(entry, mapping);
				ExtensibleObjects parsedObjects = agent.getObjectTranslator().parseInputObjects(ldapObject);
				for (ExtensibleObject object : parsedObjects.getObjects()) {
					if (debugEnabled) {
						agent.debugObject("Got Soffid object", object, "  ");
					}
					AuthoritativeChange change = null;

					if (isUser(entry) && ! crossChange(object, ldapObject))
						change = agent.parseUserChange(object, ldapObject);
					if (change == null)
						change = agent.parseGroupChange(object);
					if (change == null)
						change = agent.parseCustomObjectChange(object);
					if (change != null) {
						boolean ignore = false;
						if (entry.getDN().contains("\\0ADEL:") && entry.getDN().contains("CN=Deleted Objects")) {
							if (change.getUser() != null)
								change.getUser().setActiu(false);
							if (change.getGroup() != null)
								change.getGroup().setObsolet(true);
							if (change.getObject() != null) {
								new RemoteServiceLocator().getCustomObjectService()
										.deleteCustomObject(change.getObject());
								ignore = true;
							}
						}
						if (!ignore) {
							change.setSourceSystem(dispatcher.getCodi());
							boolean remove = entry.getAttribute("isDeleted") != null
									&& "TRUE".equals(entry.getAttribute("isDeleted").getStringValue());
							new es.caib.seycon.ng.remote.RemoteServiceLocator().getServerService()
									.processAuthoritativeChange(change, remove);
						}
					}
				}
			} else {
				if (entry.getDN().contains("\\0ADEL:") && entry.getDN().contains("CN=Deleted Objects")) {
					// Account deleted
				} else if (isUser(entry)) {
					String accountName = null;
					for (ExtensibleObjectMapping mapping : agent.objectMappings) {
						if (mapping.getSoffidObject().equals(es.caib.seycon.ng.comu.SoffidObjectType.OBJECT_ACCOUNT)) {
							accountName = agent.generateAccountName(entry, mapping, "accountName");
						}
					}
					String ll = entry.getAttribute("usnChanged").getStringValue();
					if (debugEnabled)
						log.info("Reconcile account name = " + accountName+ " usnChanged = "+ll);
					if (accountName != null) {
						new es.caib.seycon.ng.remote.RemoteServiceLocator().getServerService()
								.reconcileAccount(dispatcher.getCodi(), accountName);
					}
				}
			}
		} catch (Exception e) {
			log.warn("Error processing authortative change", e);
		}

	}

	private boolean crossChange(ExtensibleObject soffidObject, ExtensibleObject ldapObject) throws InternalErrorException, ParseException {
		try {
			String userName = (String) soffidObject.getAttribute("userName");
			if (userName == null)
				return false;
			Usuari current = agent.getServer().getUserInfo(userName, null);
			String when = (String) ldapObject.getAttribute("whenChanged");
			if (when == null) return false;
			Date d = lastChangeToDate(when);
			if (current.getModifiedOn() != null && current.getModifiedOn().getTime().after(d))
				return true;
			else
				return false;
		} catch (UnknownUserException e) {
			return false;
		}
	}


	private boolean isUser(LDAPEntry entry) {
		LDAPAttribute accountAttribute = entry.getAttribute("sAMAccountName");
		if (accountAttribute == null)
			return false;
		boolean user = false;
		boolean computer = false;
		for (String v : entry.getAttribute("objectClass").getStringValueArray()) {
			if (v.equalsIgnoreCase("user"))
				user = true;
			if (v.equalsIgnoreCase("computer"))
				computer = true;
		}
		return user && !computer;
	}

	public void setDispatcher(Dispatcher dispatcher) {
		this.dispatcher = dispatcher;
	}

}
