package com.soffid.iam.sync.agent;

import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPSocketFactory;

public class SecureLDAPConnection extends LDAPConnection {

	public SecureLDAPConnection() {
		super();
	}

	public SecureLDAPConnection(int arg0) {
		super(arg0);
	}

	public SecureLDAPConnection(LDAPSocketFactory arg0) {
		super(arg0);
	}

	@Override
	public boolean isTLS() {
		return true;
	}

}
