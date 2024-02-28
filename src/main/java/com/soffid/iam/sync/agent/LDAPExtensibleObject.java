package com.soffid.iam.sync.agent;

import java.io.IOException;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.msdtyp.SecurityDescriptor;
import com.hierynomus.msdtyp.ace.ACE;
import com.hierynomus.msdtyp.ace.AceType;
import com.hierynomus.msdtyp.ace.AceType2;
import com.hierynomus.smb.SMBBuffer;
import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPReferralException;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.LDAPSearchResults;

import es.caib.seycon.ng.exception.InternalErrorException;
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
		keys.add("immutableId");
		keys.add("userCannotChangePassword");
		return keys;
	}
	

	@Override
	public boolean containsKey(Object key) {
		if ("dn".equals(key))
			return true;
		else if ("lastLogon".equals(key))
			return true;
		else if ("lastLogonIgnoreServers".equals(key))
			return true;
		else if ("immutableId".equals(key))
			return true;
		else if ("userCannotChangePassword".equals(key))
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
			return calculateLastLogon (false);
		
		if ("lastLogonIgnoreServers".equals(attribute))
		{
			Object r = super.getAttribute(attribute);
			if (r == null)
				r = "";
			return r;
		}
		
		if ("userCannotChangePassword".equals(attribute)) {
			return querySamCanChangePassword();
		}
		
		if ("lastLogonStrict".equals(attribute))
			return calculateLastLogon (true);
		
		if ("immutableId".equals(attribute))
		{
			LDAPAttribute att = entry.getAttribute("objectGUID");
			if (att == null)
				return null;
			else
				return Base64.encodeBytes(att.getByteValue());
		}

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
		else if (att.getName().equalsIgnoreCase("userParameters"))
		{
			try {
				AttributesEncoder e = new AttributesEncoder(att.getByteValue());
				return e.parse();
			} catch (IOException e) {
				throw new RuntimeException("Error parsing userParameters", e);
			}
		}
		else if (att.getStringValueArray().length == 1)
			return att.getStringValue();
		else
			return att.getStringValueArray();
	}

	private boolean querySamCanChangePassword() {
		try {
			LDAPConnection conn = pool.getConnection();
			try {
				LDAPEntry ee = conn.read(entry.getDN(), new String[] {"ntSecurityDescriptor"});
				SMBBuffer buff = new SMBBuffer(ee.getAttribute("nTSecurityDescriptor").getByteValue());
				SecurityDescriptor d = SecurityDescriptor.read(buff);
				ACE aceEveryone = null;
				ACE aceSelf = null;
				for (ACE ace: d.getDacl().getAces()) {
					if (ace.getAceHeader().getAceType() == AceType.ACCESS_DENIED_OBJECT_ACE_TYPE &&
							ace instanceof AceType2 &&
							((AceType2)ace).getObjectType().toString()
								.equals(CustomizableActiveDirectoryAgent.PASSWORD_OBJECT) &&
							ace.getAccessMask() == AccessMask.FILE_WRITE_ATTRIBUTES.getValue()) {
						if (ace.getSid().toString().equals(CustomizableActiveDirectoryAgent.SID_SELF)) 
							aceSelf = ace;
						if (ace.getSid().toString().equals(CustomizableActiveDirectoryAgent.SID_EVERYONE)) 
							aceEveryone = ace;
					}
				}
				return aceSelf != null && aceEveryone != null;
			} finally {
				pool.returnConnection();
			}
		} catch (Exception e) {
			throw new RuntimeException("Error parsing ntSecurityDescriptor", e);
		}
	}


	private String parseGUID(byte[] byteValue) {
		return GUIDParser.format(byteValue);
	}

	Long lastLogon = null;
    private String calculateLastLogon(final boolean fail) {
    	if (lastLogon != null)
    		return lastLogon.toString();
    	if (pool == null)
    		return null;
    	
    	pool.getLog().info("Calculating lastLogon for "+entry.getDN());
    	if (pool.getChildPools() == null)
    	{
    		try {
				createChildPools (pool);
			} catch (InternalErrorException e) {
				if (fail)
					throw new RuntimeException("Error connecting to domain controllers", e);
				else
					return null;
			}
    		
    	}
    	String exclusions = (String) get ("lastLogonIgnoreServers");
    	final String exclusionsArray[] = exclusions == null ? new String[0] : exclusions.split("[ ,]+");
    	Arrays.sort(exclusionsArray);
    	
    	LinkedList<Thread> poolThread = new LinkedList<Thread>();
    	for (final LDAPPool p: pool.getChildPools())
    	{
    		Thread th = new Thread ( new Runnable() {
				public void run() {
					try {
						String name = p.getLdapHost();
						int pos = Arrays.binarySearch(exclusionsArray,  name);
						if ( pos >= 0 )
							pool.getLog().info("Ignoring lastLogon from "+p.getLdapHost());
						else
						{
							pool.getLog().info("Getting lastLogon from "+p.getLdapHost());
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
								pool.getLog().info("Error querying lastLogon attribute on "+p.getLdapHost(), e);
								if (fail)
									throw new RuntimeException("Error querying lastLogon attribute on "+p.getLdapHost(), e);
							} finally {
								p.returnConnection();
							}
						}
					} finally {
					}
				}
			});
    		th.setName("Get last logon from "+p.getLdapHost());
    		poolThread.add(th);
    		th.start();
    	}
    	
    	for (Thread th: poolThread)
    	{
    		try {
				th.join(5000);
			} catch (InterruptedException e) {
				log.info("Error accessing "+th.getName());
			}
    	}
    	if (lastLogon == null)
    		return null;
    	else
    		return lastLogon.toString();
    	
	}

    Log log = LogFactory.getLog(getClass());
    private void createChildPools(LDAPPool pool2) throws InternalErrorException {
		LDAPConnection conn;
		LinkedList<LDAPPool> children = new LinkedList<LDAPPool>();
		try {
			log.info("Resolving domain controllers for "+pool2.getLdapHost());
			
			conn = pool.getConnection();
			LDAPSearchConstraints constraints = new LDAPSearchConstraints(conn.getConstraints());
			LDAPSearchResults query = conn.search(pool.getBaseDN(),
						LDAPConnection.SCOPE_SUB, 
						"(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
						null, false,
						constraints);
			while (query.hasMore()) {
				try {
					LDAPEntry entry = query.next();
					LDAPAttribute dnsName = entry.getAttribute("dNSHostName");
					if (dnsName != null)
					{
						String hostName = dnsName.getStringValue();
						log.info("  Found domain controller: "+hostName);
						children.add( createChildPool(pool.getBaseDN(), hostName, pool2));
					}
				} catch (LDAPReferralException e)
				{
				}
			}			

		} catch (UnknownHostException e) {
			log.warn("Error resolving host "+pool2.getLdapHost(), e);
		} catch (LDAPException e1) {
			log.warn("Error querying domain controllers ", e1);
		} catch (Exception e2) {
			throw new InternalErrorException("Error querying domain controllers", e2);
		} finally {
			pool.returnConnection();
		}
		pool.setChildPools(children);
	}

	private LDAPPool createChildPool(String base, String host, LDAPPool parent) {
		LDAPPool pool = new LDAPPool();
		pool.setUseSsl( false );
		pool.setBaseDN( base );
		pool.setLdapHost(host);
		pool.setLdapPort( LDAPConnection.DEFAULT_PORT );
		pool.setLdapVersion(parent.getLdapVersion());
		pool.setLoginDN(parent.getLoginDN());
		pool.setPassword(parent.getPassword());
		pool.setAlwaysTrust(parent.isAlwaysTrust());
		pool.setFollowReferrals(parent.isFollowReferrals());
		pool.setDebug (parent.isDebug());
		pool.setLog(parent.getLog());
		return pool;
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


