import java.util.Iterator;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPControl;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPReferralException;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.LDAPSearchResults;

import es.caib.seycon.ng.exception.InternalErrorException;

public class Undelete {
	private static final String USER_CN = "Deleted user";
	private static final String USER_DN = "cn=Deleted user,cn=Users,dc=ad2022,dc=bubu,dc=lab";

	public static void main(String args[]) throws LDAPException {
		new Undelete().test();
	}

	private void test() throws LDAPException {
		LDAPConnection c = new LDAPConnection();
		c.connect("ws2022.ad2022.bubu.lab", LDAPConnection.DEFAULT_PORT);
		
		c.bind("Administrator", "Test70.");
		
//		createUser(c);
		
//		search(c);
		
//		delete(c);
		
		search(c);
		
//		undelete(c);
	}

	private void search(LDAPConnection c) throws LDAPException {
		System.out.println("\n*********************\n");
		LDAPSearchConstraints constraints = new LDAPSearchConstraints(c.getConstraints());
		constraints.setReferralFollowing(false);
		constraints.setControls( 
				new LDAPControl [] {
					new LDAPControl ("1.2.840.113556.1.4.417", true, null)
				});

		LDAPSearchResults query = c.search("dc=ad2022,dc=bubu,dc=lab",
				LDAPConnection.SCOPE_SUB, "(&(objectClass=user)(sAMAccountName=undeleted))", null, false,
				constraints);
		
		while (query.hasMore()) {
			try {
				LDAPEntry entry = query.next();
				System.out.println(entry.getDN());
			} catch (LDAPReferralException e) {
				for (String s: e.getReferrals()) {
//					System.out.println("Ignoring "+s);
				}
			}
		}
	}

	private void undelete(LDAPConnection c) throws LDAPException {
		System.out.println("\n*********************\n");
		LDAPSearchConstraints constraints = new LDAPSearchConstraints(c.getConstraints());
		constraints.setReferralFollowing(false);
		constraints.setControls( 
				new LDAPControl [] {
					new LDAPControl ("1.2.840.113556.1.4.417", true, null)
				});

		LDAPSearchResults query = c.search("dc=ad2022,dc=bubu,dc=lab",
				LDAPConnection.SCOPE_SUB, "(&(objectClass=user)(sAMAccountName=undeleted))", null, false,
				constraints);
		
		while (query.hasMore()) {
			try {
				LDAPEntry entry = query.next();
				System.out.println(entry.getDN());
				for (Iterator it = entry.getAttributeSet().iterator(); it.hasNext();) {
					LDAPAttribute att = (LDAPAttribute) it.next();
					System.out.println(" > "+att.getName()+": "+att.getStringValue());
				}
				c.modify(entry.getDN(), new LDAPModification[] {
//						new LDAPModification(LDAPModification.REPLACE, new LDAPAttribute("cn", USER_CN)),
						new LDAPModification(LDAPModification.DELETE, new LDAPAttribute("isDeleted")),
						new LDAPModification(LDAPModification.REPLACE, new LDAPAttribute("distinguishedName", USER_DN)),
				}, constraints);
//				c.rename(entry.getDN(), USER_DN, false, constraints);
				break;
			} catch (LDAPReferralException e) {
				for (String s: e.getReferrals()) {
//					System.out.println("Ignoring "+s);
				}
			}
		}
	}

	private void delete(LDAPConnection c) throws LDAPException {
		c.delete(USER_DN);
	}

	private void createUser(LDAPConnection c) throws LDAPException {
		LDAPAttributeSet attributeSet = new LDAPAttributeSet();
		
		attributeSet.add(new LDAPAttribute("objectclass", "user"));
		attributeSet.add(new LDAPAttribute("sAMAccountName", "undeleted"));
		attributeSet.add(new LDAPAttribute("objectclass", "user"));
		attributeSet.add(new LDAPAttribute("cn", USER_CN));

		LDAPEntry entry = new LDAPEntry(USER_DN, attributeSet);
		
		c.add(entry);
	}
}
