package com.soffid.iam.sync.agent;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import com.novell.ldap.LDAPAttribute;
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
		else if (att.getStringValueArray().length == 1)
			return att.getStringValue();
		else
			return att.getStringValueArray();
	}

    private final static int MASK_8_BIT = 0xff;
    private final static long MASK_32_BIT = 0xffffffffL;
    private final static long MASK_48_BIT = 0xffffffffffffL;

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
}


