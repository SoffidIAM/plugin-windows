package com.soffid.iam.sync.agent;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidParameterException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.util.encoders.Hex;

public class AttributesEncoder {
	Log log = LogFactory.getLog(getClass());
	byte data[] = null;
	public AttributesEncoder (byte data []) throws UnsupportedEncodingException
	{
		if (data != null)
			this.data = new String( data, "UTF-8").getBytes("UTF-16LE");
	}	
	
	public byte[] getBytes () throws UnsupportedEncodingException {
		if (data == null)
			return null;
		return new String(data, "UTF-16LE").getBytes("UTF-8");
	}
	
	public Map<String,String> parse () throws UnsupportedEncodingException
	{
		return parse (false);
	}
	
	public Map<String,String> parse (boolean raw) throws UnsupportedEncodingException
	{
		Map<String,String> result = new HashMap<String, String>();
		if (data != null && data.length >= 104)
		{
			int character = toShort(96);
			if (character != 'P')
			{
				log.info("Data corrupt reading attributes value. Missing data signature");
				return result;
			}
			int count = toShort(98);
			int pos = 100;
			for (int i = 0; i < count; i++)
			{
				pos = readVar (pos, result, raw);
			}
		}
		return result;
	}
	
	public void put (String name, String value) throws IOException {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		Map<String, String> vars = parse();
		if (value == null)
			vars.remove(name);
		else
			vars.put(name, value);
		if (data == null || data.length < 100)
		{
			byte b [] = new byte[100];
			b[96] = 'P';
			b[97] = 0;
			out.write( b );
		}
		else
			out.write( data, 0, 98 );
		
		Set<String> names = vars.keySet();
		out.write ( toBytes( names.size()) );
		for (String n: names)
		{
			String v = vars.get(n); 
			byte[] binaryName = n.getBytes("UTF-16LE");
			byte[] binaryValue;
			if ( v.startsWith("0x"))
			{
				binaryValue = v.substring(2).getBytes("UTF-8");
			}
			else if ( n.endsWith("W") )
			{
				binaryValue = Hex.encode((v+"\0").getBytes("UTF-16LE"));
			}
			else
			{
				binaryValue = Hex.encode((v+"\0").getBytes("UTF-8"));
			}
			out.write( toBytes(binaryName.length));
			out.write( toBytes(binaryValue.length));
			out.write(toBytes(1));
			out.write(binaryName);
			out.write(binaryValue);
		}
		data = out.toByteArray();
	}
	
	
	private int readVar(int pos, Map<String, String> result, boolean raw) throws UnsupportedEncodingException {
		int nameLength = toShort(pos) ;
		int valueLength = toShort (pos+2) ;
		int type = toShort( pos+4);
		pos = pos + 6;
		byte name[] = Arrays.copyOfRange(data, pos, pos+nameLength);
		pos += nameLength;
		byte value[] = Arrays.copyOfRange(data, pos, pos+valueLength);
		pos += valueLength;
		
		String valueString = new String(value, "UTF-8");
		if (raw || valueString.length() == 2 || valueString.length() == 8)
			result.put(new String(name, "UTF-16LE"),  "0x"+valueString);
		else if (valueString.endsWith("0000"))
			result.put(new String(name, "UTF-16LE"), new String(Hex.decode(valueString.substring(0,valueString.length()-4)), "UTF-16LE"));
		else if (valueString.endsWith("00"))
			result.put(new String(name, "UTF-16LE"), new String(Hex.decode(valueString.substring(0, valueString.length()-2)), "UTF-8"));
		else
			result.put(new String(name, "UTF-16LE"), new String(Hex.decode(valueString), "UTF-8"));
		return pos;
	}

	private int toShort(int pos)
	{
		return ( ((int)data[pos]) & 255 ) + 256 * ( ((int)data[pos+1]) & 255 );  
	}

	private byte[] toBytes (int i)
	{
		byte[] b = new byte[2];
		b [ 0 ] = (byte) (i % 256);
		b [ 1 ] = (byte) (i / 256);
		return b;
	}
}
 