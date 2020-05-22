package com.soffid.iam.sync.agent2;

import java.rmi.RemoteException;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.Map;
import java.util.Set;
import java.util.Stack;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.soffid.iam.api.CustomObject;
import com.soffid.iam.api.Group;
import com.soffid.iam.sync.agent.CustomizableActiveDirectoryAgent2;
import com.soffid.iam.sync.agent.LDAPExtensibleObject;
import com.soffid.iam.sync.intf.CustomObjectMgr;

import es.caib.seycon.ng.comu.Grup;
import es.caib.seycon.ng.comu.SoffidObjectType;
import es.caib.seycon.ng.comu.Usuari;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.sync.engine.Watchdog;
import es.caib.seycon.ng.sync.engine.extobj.CustomExtensibleObject;
import es.caib.seycon.ng.sync.intf.AuthoritativeChange;
import es.caib.seycon.ng.sync.intf.AuthoritativeChangeIdentifier;
import es.caib.seycon.ng.sync.intf.ExtensibleObject;
import es.caib.seycon.ng.sync.intf.ExtensibleObjectMapping;
import es.caib.seycon.ng.sync.intf.ExtensibleObjects;

public class CustomizableActiveDirectoryAgent extends CustomizableActiveDirectoryAgent2 implements CustomObjectMgr {

	public CustomizableActiveDirectoryAgent() throws RemoteException {
		super();
	}

	public void updateCustomObject(CustomObject obj) throws RemoteException, InternalErrorException {
		CustomExtensibleObject sourceObject = new CustomExtensibleObject(obj, getServer());
		ExtensibleObjects objects = objectTranslator
				.generateObjects(sourceObject);
		Watchdog.instance().interruptMe(getDispatcher().getTimeout());
		try {
			updateObjects(obj.getName(), obj.getName(), objects, sourceObject, null /*always apply */);
		} catch (InternalErrorException e) {
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException(e.getMessage(), e);
		} finally {
			Watchdog.instance().dontDisturb();
		}
	}

	public void removeCustomObject(CustomObject obj) throws RemoteException, InternalErrorException {
		ExtensibleObjects objects;
		ExtensibleObject sourceObject;

		
		objects = objectTranslator.generateObjects(sourceObject = new CustomExtensibleObject(obj, getServer()));
		Watchdog.instance().interruptMe(getDispatcher().getTimeout());
		try {
			removeObjects(null, objects, sourceObject, null /*always apply */);
		} catch (InternalErrorException e) {
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException(e.getMessage(), e);
		} finally {
			Watchdog.instance().dontDisturb();
		}

	}



	public Collection<AuthoritativeChange> getChanges(String nextChange)
			throws InternalErrorException {
		Collection<AuthoritativeChange> changes = new LinkedList<AuthoritativeChange>();
		Watchdog.instance().interruptMe(getDispatcher().getLongTimeout());
		try {
			log.info("Getting changes from " + nextChange);
			if (searches == null)
			{
				searches = new Stack<CustomizableActiveDirectoryAgent.LdapSearch>();
				for (String domain: domainHost.keySet())
				{
					for (ExtensibleObjectMapping mapping : objectMappings) {
						if (mapping.getSoffidObject().equals(SoffidObjectType.OBJECT_AUTHORITATIVE_CHANGE) ||
								mapping.getSoffidObject().equals(SoffidObjectType.OBJECT_USER) ||
								mapping.getSoffidObject().equals(SoffidObjectType.OBJECT_GROUP) ||
								mapping.getSoffidObject().equals(SoffidObjectType.OBJECT_CUSTOM)) {
							searches.push( new LdapSearch(mapping, domain, nextChange) );
							if (debugEnabled)
								log.info("Planned search on domain "+domain);
						}
					}
				}
			}
			while (changes.isEmpty())
			{
				LdapSearch currentSearch = null;
				do
				{
					if (searches.isEmpty())
						return changes;
					LdapSearch s = searches.peek();
					if (s.finished)
					{
						if (debugEnabled)
							log.info("Finished search on domain "+s.domain);
						searches.pop();
					}
					else
						currentSearch = s;
				} while (currentSearch == null);
					
				LinkedList<ExtensibleObject> objects = getLdapObjects(currentSearch);
	
				for (ExtensibleObject ldapObject : objects) 
				{
					if (debugEnabled)
					{
						debugObject("LDAP object", ldapObject, "  ");
					}
					ExtensibleObjects parsedObjects = objectTranslator
							.parseInputObjects(ldapObject);
					for (ExtensibleObject object : parsedObjects.getObjects()) {
						if (debugEnabled)
						{
							debugObject("Soffid object", object, "  ");
						}
						parseUser(changes, object);
						parseGroup(changes, object);
						parseCustomObject(changes, object);
					}
				}
			}
		} catch (LDAPException e) {
			throw new InternalErrorException("Error getting accounts list", e);
		} catch (InternalErrorException e) {
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException(e.getMessage(), e);
		} finally {
			Watchdog.instance().dontDisturb();
		}
		return changes;
	}

	private void parseUser(Collection<AuthoritativeChange> changes, ExtensibleObject object)
			throws InternalErrorException {
		Usuari user = vom.parseUsuari(object);
		if (user != null) {
			AuthoritativeChange change = new AuthoritativeChange();

			AuthoritativeChangeIdentifier id = new AuthoritativeChangeIdentifier();
			change.setId(id);
			id.setChangeId(null);
			id.setEmployeeId(user.getCodi());
			id.setDate(new Date());

			change.setUser(user);

			Object groups = object.getAttribute("secondaryGroups");
			if (groups instanceof Collection) {
				Set<String> groupsList = new HashSet<String>();
				for (Object group : (Collection<Object>) object) {
					if (group instanceof String) {
						groupsList.add((String) group);
					} else if (group instanceof ExtensibleObject) {
						Object name = (String) ((ExtensibleObject) group)
								.getAttribute("name");
						if (name != null)
							groupsList.add(name.toString());
					} else if (group instanceof Group) {
						groupsList.add(((Group) group).getName());
					} else if (group instanceof Grup) {
						groupsList.add(((Grup) group).getCodi());
					}
				}
				change.setGroups(groupsList);
			}

			Object attributes = object.getAttribute("attributes");
			if (attributes instanceof Map) {
				Map<String, Object> attributesMap = new HashMap<String, Object>();
				for (Object attributeName : ((Map) attributes)
						.keySet()) {
					attributesMap
							.put((String) attributeName,
									(String) vom
											.toSingleString(((Map) attributes)
													.get(attributeName)));
				}
				change.setAttributes(attributesMap);
			}

			changes.add(change);
		}
	}

	private void parseGroup(Collection<AuthoritativeChange> changes, ExtensibleObject object)
			throws InternalErrorException {
		Grup group = vom.parseGroup(object);
		if (group != null) {
			AuthoritativeChange change = new AuthoritativeChange();

			AuthoritativeChangeIdentifier id = new AuthoritativeChangeIdentifier();
			change.setId(id);
			id.setChangeId(null);
			id.setEmployeeId("G:"+group.getCodi());
			id.setDate(new Date());

			change.setGroup(group);

			changes.add(change);
		}
	}


	public ExtensibleObject getNativeObject(SoffidObjectType type, String object1, String object2) throws InternalErrorException {
		try {
			String samAccountName =
					type == SoffidObjectType.OBJECT_CUSTOM ?
							null :
							object1;
			ExtensibleObject sourceObject = getExtensibleObject(type, object1, object2);
			
			if (debugEnabled)
			{
				debugObject("Searching for object", sourceObject, "  ");
			}

			ExtensibleObjects targetObjects = new ExtensibleObjects();
			for (ExtensibleObjectMapping mapping: objectMappings)
			{
				if (mapping.getSoffidObject().getValue().equals(sourceObject.getObjectType()))
				{
	    			ExtensibleObject to = objectTranslator.generateObject(sourceObject, mapping,  true);
	    			if (to != null)
	    			{
	    				if (debugEnabled)
	    					log.info("Searching for "+samAccountName);
	    				LDAPEntry entry = searchSamAccount(to, samAccountName);
	    				if (entry != null)
	    				{
	    					ExtensibleObject s = new LDAPExtensibleObject(to.getObjectType(), entry,
	    							getEntryPool(entry));
		    				if (debugEnabled)
		    					debugEntry("Found AD object", entry.getDN(), entry.getAttributeSet());
	    					ExtensibleObject r = new ExtensibleObject();
	    					r.setObjectType(to.getObjectType());
	    					for (LDAPAttribute key: (Collection<LDAPAttribute>)entry.getAttributeSet())
	    					{
	    						r.setAttribute(key.getName(), s.getAttribute(key.getName()));
	    					}
	    					return r;
	    				}
	    			}
				}
			}

			return null;
		} catch (InternalErrorException e) {
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException("Error retrieving object information", e);
		}
	}


	public ExtensibleObject getSoffidObject(SoffidObjectType type, String object1, String object2) throws InternalErrorException {
		try {
			String samAccountName =
					type == SoffidObjectType.OBJECT_CUSTOM ?
							null :
							object1;
			ExtensibleObject sourceObject = getExtensibleObject(type, object1, object2);

			ExtensibleObjects targetObjects = new ExtensibleObjects();
			for (ExtensibleObjectMapping mapping: objectMappings)
			{
				if (mapping.getSoffidObject().getValue().equals(sourceObject.getObjectType()))
				{
	    			ExtensibleObject to = objectTranslator.generateObject(sourceObject, mapping,  true);
	    			if (to != null)
	    			{
	    				LDAPEntry entry = searchSamAccount(to, samAccountName);
	    				if (entry != null)
	    				{
	    					ExtensibleObject s = new LDAPExtensibleObject(to.getObjectType(), entry,
	    							getEntryPool(entry));
	    					for (ExtensibleObject so: objectTranslator.parseInputObjects(s).getObjects())
	    					{
	    						return so;
	    					}
	    				}
	    			}
				}
			}

			return null;
		} catch (InternalErrorException e) {
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException("Error retrieving object information", e);
		}
	}

	@Override
	protected AuthoritativeChange parseCustomObjectChange(ExtensibleObject object)
			throws InternalErrorException {
		CustomObject obj = vom.parseCustomObject(object);
		if (obj != null) {
			AuthoritativeChange change = new AuthoritativeChange();

			AuthoritativeChangeIdentifier id = new AuthoritativeChangeIdentifier();
			change.setId(id);
			id.setChangeId(null);
			id.setEmployeeId("group:"+obj.getName());
			id.setDate(new Date());

			change.setObject(obj);
			return change;
		}
		else
			return null;
	}
}
