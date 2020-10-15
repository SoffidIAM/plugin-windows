import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPEntry;
import com.soffid.iam.sync.agent.GUIDParser;

import es.caib.seycon.util.Base64;

public class GuidTest {
	public static void main(String args[]) throws Exception {
		LDAPConnection c = new LDAPConnection();

		System.out.println("Connecting...");
		c.connect("localhost", 1389);
		

		c.bind(LDAPConnection.LDAP_V3, "diba\\sgsi.svcgi", "_ng8shie4c".getBytes("UTF-8"));

		System.out.println("Connected");

		LDAPEntry e = c.read("CN=provaesbfed,OU=prova,OU=STP,OU=Personals,OU=Administradors,dc=corpo,dc=ad,dc=diba,dc=es");
		LDAPAttribute att = e.getAttribute("objectGUID");
		System.out.println(att.getStringValue());
	
		byte[] b = att.getByteValue();
		
		System.out.println(b.length);
		String guuid = GUIDParser.format(b);
		System.out.println( guuid );
		
		System.out.println( Base64.encodeBytes(b));
		
		byte [] b2 = GUIDParser.parseGuid(guuid);
		System.out.println( Base64.encodeBytes(b2));
		System.out.println( GUIDParser.format(b2));
		
	}
	
}
