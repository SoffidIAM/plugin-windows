package com.soffid.iam.sync.agent;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.UUID;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPEntry;

import es.caib.seycon.ng.sync.intf.ExtensibleObject;
import es.caib.seycon.util.Base64;

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
		else if ("lastLogon".equals(key))
			return true;
		else
			return entry.getAttribute((String)key) != null;
	}

	private LDAPEntry entry;
	private LDAPPool pool;

	public LDAPExtensibleObject (String objectType, LDAPEntry entry, LDAPPool sourcePool)
	{
		super();
		this.entry = entry;
		this.pool = sourcePool;
		setObjectType(objectType);
	}

	@Override
	public Object getAttribute (String attribute)
	{
		if ("dn".equals(attribute))
			return entry.getDN();
		
		if ("lastLogon".equals(attribute))
			return calculateLastLogon ();
		
		LDAPAttribute att = entry.getAttribute(attribute);
		if (att == null)
			return null;
		
		if (att.getName().equalsIgnoreCase("sIDHistory"))
		{
			byte[][] v = att.getByteValueArray();
			String [] r = new String[v.length];
			for (int i=0; i<v.length; i++)
				r [i] = parseSid(v[i]);
			return r;
		}
		else if (att.getName().equalsIgnoreCase("objectSid"))
		{
			return parseSid(att.getByteValue());
		}
		else if (att.getName().equalsIgnoreCase("objectGUID"))
		{
			return parseGUID(att.getByteValue());
		}
		else if (att.getStringValueArray().length == 1)
			return att.getStringValue();
		else
			return att.getStringValueArray();
	}

	private String parseGUID(byte[] byteValue) {
		return UUID.nameUUIDFromBytes(byteValue).toString();
	}

	Long lastLogon = null;
    private String calculateLastLogon() {
    	if (lastLogon != null)
    		return lastLogon.toString();
    	if (pool == null)
    		return null;
    	
    	pool.getLog().info("Calculating lastLogon for "+entry.getDN());
    	for (LDAPPool p: pool.getChildPools())
    	{
        	pool.getLog().info("Connecting to "+pool.getLdapHost());
    		LDAPConnection c = null;
    		try {
    			c = p.getConnection();
    			LDAPEntry entry2 = c.read(entry.getDN(), new String[] {"lastLogon"});
    	    	LDAPAttribute lastLogonAtt = entry2.getAttribute("lastLogon");
    	    	if (lastLogonAtt != null)
    	    	{
    	    		Long newLastLogon = Long.decode(lastLogonAtt.getStringValue());
    	    		pool.getLog().info("Last logon on "+p.getLdapHost()+"="+newLastLogon);
    	    		if (lastLogon == null || newLastLogon.compareTo(lastLogon) > 0)
    	    			lastLogon = newLastLogon;
    	    	}
    		} catch (Exception e) {
    			pool.getLog().debug("Error querying lastLogon attribute on "+p.getLdapHost(), e);
    		} finally {
    			if (c != null) {
					try {
						p.closeConnection(c);
					} catch (Exception e) {
					}
    			}
    		}
    	}
    	
    	if (lastLogon == null)
    		return null;
    	else
    		return lastLogon.toString();
    	
	}

    public static String parseSid(byte[] bytes) {
        if ( bytes == null || bytes.length < 8 )
        {
            throw new IllegalArgumentException("InvalidSid. Invalid size" ); //$NON-NLS-1$
        }

        char[] hex = encodeHex( bytes );
        StringBuffer sb = new StringBuffer();

        // start with 'S'
        sb.append( 'S' );

        // revision
        int revision = Integer.parseInt( new String( hex, 0, 2 ), 16 );
        sb.append( '-' );
        sb.append( revision );

        // get count
        int count = Integer.parseInt( new String( hex, 2, 2 ), 16 );

        // check length
        if ( bytes.length != ( 8 + count * 4 ) )
        {
            throw new IllegalArgumentException("InvalidSid. Invalid size" ); //$NON-NLS-1$
        }

        // get authority, big-endian
        long authority = Long.parseLong( new String( hex, 4, 12 ), 16 );
        sb.append( '-' );
        sb.append( authority );

        // sub-authorities, little-endian
        for ( int i = 0; i < count; i++ )
        {
            StringBuffer rid = new StringBuffer();
            for ( int k = 3; k >= 0; k-- )
            {
                rid.append( hex[16 + ( i * 8 ) + ( k * 2 )] );
                rid.append( hex[16 + ( i * 8 ) + ( k * 2 ) + 1] );
            }

            long subAuthority = Long.parseLong( rid.toString(), 16 );
            sb.append( '-' );
            sb.append( subAuthority );
        }

        return sb.toString();
    }


    private static final char[] DIGITS_LOWER =
        {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
	private static char[] encodeHex(byte[]data) {
        final int l = data.length;
        final char[] out = new char[l << 1];
        // two characters form the hex value.
        for (int i = 0, j = 0; i < l; i++) {
            out[j++] = DIGITS_LOWER[(0xF0 & data[i]) >>> 4];
            out[j++] = DIGITS_LOWER[0x0F & data[i]];
        }
        return out;
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


	@Override
	public Set<String> getAttributes() {
		return keySet();
	}
}


