package com.soffid.iam.sync.agent;

import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPEntry;

import es.caib.seycon.ng.sync.intf.ExtensibleObject;

public class LDAPExtensibleObject extends ExtensibleObject
{
	
	
	@Override
	public Set<String> keySet() {
		Set<String> keys = new HashSet<String>();
		for (Iterator<LDAPAttribute> it = (Iterator<LDAPAttribute>) entry.getAttributeSet().iterator(); 
				it.hasNext();)
		{
			LDAPAttribute att = it.next();
			keys.add(att.getName());
		}
		keys.add("dn");
		return keys;
	}
	

	@Override
	public boolean containsKey(Object key) {
		if ("dn".equals(key))
			return true;
		else
			return entry.getAttribute((String)key) != null;
	}

	private LDAPEntry entry;

	public LDAPExtensibleObject (String objectType, LDAPEntry entry)
	{
		super();
		this.entry = entry;
		setObjectType(objectType);
	}

	@Override
	public Object getAttribute (String attribute)
	{
		
		if ("dn".equals(attribute))
			return entry.getDN();
		
		LDAPAttribute att = entry.getAttribute(attribute);
		if (att == null)
			return null;
		
		if (att.getStringValueArray().length == 1)
			return att.getStringValue();
		else
			return att.getStringValueArray();
	}

	@Override
	public boolean equals (Object o)
	{
		if (o instanceof LDAPExtensibleObject)
			return entry.getDN().equals (((LDAPExtensibleObject) o).entry.getDN());
		else
			return false;
	}

	@Override
	public int hashCode ()
	{
		return entry.getDN().hashCode();
	}
}


