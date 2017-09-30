package com.soffid.iam.sync.agent;

import java.rmi.RemoteException;
import java.util.Iterator;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPEntry;

import es.caib.seycon.ng.comu.ObjectMappingTrigger;
import es.caib.seycon.ng.comu.Rol;
import es.caib.seycon.ng.comu.RolGrant;
import es.caib.seycon.ng.comu.SoffidObjectTrigger;
import es.caib.seycon.ng.comu.SoffidObjectType;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownRoleException;
import es.caib.seycon.ng.sync.engine.extobj.GrantExtensibleObject;
import es.caib.seycon.ng.sync.intf.ExtensibleObject;
import es.caib.seycon.ng.sync.intf.ExtensibleObjectMapping;

public class CustomizableActiveDirectoryAgent2 extends
		CustomizableActiveDirectoryAgent {

	public CustomizableActiveDirectoryAgent2() throws RemoteException {
		super();
	}

	protected boolean runTrigger (SoffidObjectTrigger triggerType,
			ExtensibleObject soffidObject,
			ExtensibleObject adObject,
			LDAPEntry currentEntry) throws InternalErrorException
	{
		SoffidObjectType sot = SoffidObjectType.fromString(soffidObject.getObjectType());
		for ( ExtensibleObjectMapping eom : objectTranslator.getObjectsBySoffidType(sot))
		{
			if (adObject == null || adObject.getObjectType().equals(eom.getSystemObject()))
			{
				for ( ObjectMappingTrigger trigger: eom.getTriggers())
				{
					if (trigger.getTrigger().equals (triggerType))
					{
						ExtensibleObject eo = new ExtensibleObject();
						eo.setAttribute("source", soffidObject);
						eo.setAttribute("newObject", adObject);
						if ( currentEntry != null)
						{
							ExtensibleObject old = buildExtensibleObject(currentEntry);
							eo.setAttribute("oldObject", old);
						}
						if ( ! objectTranslator.evalExpression(eo, trigger.getScript()) )
						{
							log.info("Trigger "+triggerType+" returned false");
							if (debugEnabled)
							{
								if (currentEntry != null)
									debugEntry("old object", currentEntry.getDN(), currentEntry.getAttributeSet());
								if (adObject != null)
									debugObject("new object", adObject, "  ");
							}
							return false;
						}
					}
				}
			}
		}
		return true;
		
	}

	protected boolean runGrantTrigger (SoffidObjectTrigger triggerType,
			String group, String user,
			LDAPEntry groupEntry, LDAPEntry userEntry, boolean add) throws InternalErrorException
	{
		for ( ExtensibleObjectMapping eom : objectTranslator.getObjects())
		{
			if (eom.getSoffidObject().equals (SoffidObjectType.OBJECT_GRANT) ||
				eom.getSoffidObject().equals (SoffidObjectType.OBJECT_GRANTED_GROUP) ||
				eom.getSoffidObject().equals (SoffidObjectType.OBJECT_GRANTED_ROLE) ||
				eom.getSoffidObject().equals (SoffidObjectType.OBJECT_ALL_GRANTED_GROUP) ||
				eom.getSoffidObject().equals (SoffidObjectType.OBJECT_ALL_GRANTED_ROLES))
			{
				for ( ObjectMappingTrigger trigger: eom.getTriggers())
				{
					if (trigger.getTrigger().equals (triggerType))
					{

						RolGrant rg = new RolGrant();
						rg.setRolName(group);
						rg.setOwnerAccountName(user);
						rg.setOwnerDispatcher(getCodi());
						rg.setDispatcher(getCodi());
						try
						{
							Rol ri = getServer().getRoleInfo(group, getDispatcher().getCodi());
							if (ri != null)
							{
								rg.setIdRol(ri.getId());
								rg.setInformationSystem(ri.getCodiAplicacio());
								// Ignore group only grants
								if (eom.getSoffidObject().equals (SoffidObjectType.OBJECT_GRANTED_GROUP) ||
										eom.getSoffidObject().equals (SoffidObjectType.OBJECT_ALL_GRANTED_GROUP) )
									continue;
							} else {
								// Ignore role only grants
								if (eom.getSoffidObject().equals (SoffidObjectType.OBJECT_GRANTED_ROLE) ||
										eom.getSoffidObject().equals (SoffidObjectType.OBJECT_ALL_GRANTED_ROLES) )
									continue;
							}
						} catch (UnknownRoleException e) 
						{
							// Ignore role only grants
							if (eom.getSoffidObject().equals (SoffidObjectType.OBJECT_GRANTED_ROLE) ||
									eom.getSoffidObject().equals (SoffidObjectType.OBJECT_ALL_GRANTED_ROLES) )
								continue;
						}
						ExtensibleObject soffidObject = new GrantExtensibleObject(rg, getServer());
						
						ExtensibleObject eo = new ExtensibleObject();
						eo.setAttribute("source", soffidObject);
						ExtensibleObject eo2 = new ExtensibleObject();
						eo2.setAttribute("group", buildExtensibleObject(groupEntry));
						eo2.setAttribute("user", buildExtensibleObject(userEntry));
						eo2.setAttribute("dn", userEntry.getDN());
						eo2.setAttribute("memberOf", groupEntry.getDN());
						eo.setAttribute( add ? "newObject": "oldObject", eo2);
						if ( ! objectTranslator.evalExpression(eo, trigger.getScript()) )
						{
							log.info("Trigger "+triggerType+" returned false");
							if (debugEnabled)
							{
								debugModifications("Group", groupEntry.getDN(), groupEntry.getAttributeSet());
								debugModifications("User", groupEntry.getDN(), groupEntry.getAttributeSet());
							}
							return false;
						}
					}
				}
			}
		}
		return true;
		
	}


	private ExtensibleObject buildExtensibleObject(LDAPEntry currentEntry) {
		ExtensibleObject old = new ExtensibleObject();
		
		for ( Iterator<LDAPAttribute> it = currentEntry.getAttributeSet().iterator(); it.hasNext(); ) {
			LDAPAttribute att = it.next();
			String [] v = att.getStringValueArray();
			if (v.length == 1)
				old.setAttribute(att.getName(), v[0]);
			else
				old.setAttribute(att.getName(), v);
		}
		old.setAttribute("dn", currentEntry.getDN());
		return old;
	}
	
	@Override
	protected boolean preUpdate(ExtensibleObject soffidObject,
			ExtensibleObject adObject, LDAPEntry currentEntry)
			throws InternalErrorException {
		return runTrigger(SoffidObjectTrigger.PRE_UPDATE, soffidObject, adObject, currentEntry);
	}

	@Override
	protected boolean preInsert(ExtensibleObject soffidObject,
			ExtensibleObject adObject) throws InternalErrorException {
		return runTrigger(SoffidObjectTrigger.PRE_INSERT, soffidObject, adObject, null);
	}

	@Override
	protected boolean preDelete(ExtensibleObject soffidObject,
			LDAPEntry currentEntry) throws InternalErrorException {
		return runTrigger(SoffidObjectTrigger.PRE_DELETE, soffidObject, null, currentEntry);
	}

	@Override
	protected boolean postUpdate(ExtensibleObject soffidObject,
			ExtensibleObject adObject, LDAPEntry currentEntry)
			throws InternalErrorException {
		return runTrigger(SoffidObjectTrigger.POST_UPDATE, soffidObject, adObject, currentEntry);
	}

	@Override
	protected boolean postInsert(ExtensibleObject soffidObject,
			ExtensibleObject adObject, LDAPEntry currentEntry)
			throws InternalErrorException {
		return runTrigger(SoffidObjectTrigger.POST_INSERT, soffidObject, adObject, currentEntry);
	}

	@Override
	protected boolean postDelete(ExtensibleObject soffidObject,
			LDAPEntry currentEntry) throws InternalErrorException {
		return runTrigger(SoffidObjectTrigger.POST_DELETE, soffidObject,  null, currentEntry);
	}

	@Override
	protected boolean postInsertTrigger(String group, String user,
			LDAPEntry groupEntry, LDAPEntry userEntry)
			throws InternalErrorException {
		return runGrantTrigger(SoffidObjectTrigger.POST_INSERT, group, user, groupEntry, userEntry, true);
	}

	@Override
	protected boolean preInsertTrigger(String group, String user,
			LDAPEntry groupEntry, LDAPEntry userEntry)
			throws InternalErrorException {
		return runGrantTrigger(SoffidObjectTrigger.PRE_INSERT, group, user, groupEntry, userEntry, true);
	}

	@Override
	protected boolean preDeleteTrigger(String group, String userName,
			LDAPEntry groupEntry, LDAPEntry userEntry)
			throws InternalErrorException {
		return runGrantTrigger(SoffidObjectTrigger.PRE_DELETE, group, userName, groupEntry, userEntry, false);
	}

	@Override
	protected boolean postDeleteTrigger(String group, String userName,
			LDAPEntry groupEntry, LDAPEntry userEntry)
			throws InternalErrorException {
		return runGrantTrigger(SoffidObjectTrigger.POST_DELETE, group, userName, groupEntry, userEntry, false);
	}

}
