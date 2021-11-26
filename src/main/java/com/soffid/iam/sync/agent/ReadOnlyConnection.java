package com.soffid.iam.sync.agent;

import java.util.Map;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPControl;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPExtendedOperation;
import com.novell.ldap.LDAPExtendedResponse;
import com.novell.ldap.LDAPMessage;
import com.novell.ldap.LDAPMessageQueue;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPResponseQueue;
import com.novell.ldap.LDAPSchema;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.LDAPSearchQueue;
import com.novell.ldap.LDAPSearchResults;
import com.novell.ldap.LDAPSocketFactory;
import com.novell.ldap.LDAPUnsolicitedNotificationListener;

public class ReadOnlyConnection extends LDAPConnection {

	private LDAPConnection conn;

	public ReadOnlyConnection(LDAPConnection p) {
		this.conn = p;
	}

	public int hashCode() {
		return conn.hashCode();
	}

	public boolean equals(Object obj) {
		return conn.equals(obj);
	}

	public String toString() {
		return conn.toString();
	}

	public Object clone() {
		return new ReadOnlyConnection( (LDAPConnection) conn.clone());
	}

	public int getProtocolVersion() {
		return conn.getProtocolVersion();
	}

	public String getAuthenticationDN() {
		return conn.getAuthenticationDN();
	}

	public String getAuthenticationMethod() {
		return conn.getAuthenticationMethod();
	}

	public Map getSaslBindProperties() {
		return conn.getSaslBindProperties();
	}

	public Object getSaslBindCallbackHandler() {
		return conn.getSaslBindCallbackHandler();
	}

	public LDAPConstraints getConstraints() {
		return conn.getConstraints();
	}

	public String getHost() {
		return conn.getHost();
	}

	public int getPort() {
		return conn.getPort();
	}

	public Object getProperty(String name) {
		return conn.getProperty(name);
	}

	public LDAPSearchConstraints getSearchConstraints() {
		return conn.getSearchConstraints();
	}

	public LDAPSocketFactory getSocketFactory() {
		return conn.getSocketFactory();
	}

	public boolean isBound() {
		return conn.isBound();
	}

	public boolean isConnected() {
		return conn.isConnected();
	}

	public boolean isConnectionAlive() {
		return conn.isConnectionAlive();
	}

	public boolean isTLS() {
		return conn.isTLS();
	}

	public int getSocketTimeOut() {
		return conn.getSocketTimeOut();
	}

	public void setSocketTimeOut(int timeout) {
		conn.setSocketTimeOut(timeout);
	}

	public void setConstraints(LDAPConstraints cons) {
		conn.setConstraints(cons);
	}

	public void addUnsolicitedNotificationListener(LDAPUnsolicitedNotificationListener listener) {
		conn.addUnsolicitedNotificationListener(listener);
	}

	public void removeUnsolicitedNotificationListener(LDAPUnsolicitedNotificationListener listener) {
		conn.removeUnsolicitedNotificationListener(listener);
	}

	public void startTLS() throws LDAPException {
		conn.startTLS();
	}

	public void stopTLS() throws LDAPException {
		conn.stopTLS();
	}

	public void abandon(LDAPSearchResults results) throws LDAPException {
		conn.abandon(results);
	}

	public void abandon(LDAPSearchResults results, LDAPConstraints cons) throws LDAPException {
		conn.abandon(results, cons);
	}

	public void abandon(int id) throws LDAPException {
		conn.abandon(id);
	}

	public void abandon(int id, LDAPConstraints cons) throws LDAPException {
		conn.abandon(id, cons);
	}

	public void abandon(LDAPMessageQueue queue) throws LDAPException {
		conn.abandon(queue);
	}

	public void abandon(LDAPMessageQueue queue, LDAPConstraints cons) throws LDAPException {
		conn.abandon(queue, cons);
	}

	public void add(LDAPEntry entry) throws LDAPException {
		throw new LDAPException("READONLY", 0, "Connection is read only");
	}

	public void add(LDAPEntry entry, LDAPConstraints cons) throws LDAPException {
		throw new LDAPException("READONLY", 0, "Connection is read only");
	}

	public LDAPResponseQueue add(LDAPEntry entry, LDAPResponseQueue queue) throws LDAPException {
		throw new LDAPException("READONLY", 0, "Connection is read only");
	}

	public LDAPResponseQueue add(LDAPEntry entry, LDAPResponseQueue queue, LDAPConstraints cons) throws LDAPException {
		throw new LDAPException("READONLY", 0, "Connection is read only");
	}

	public void bind(String dn, String passwd) throws LDAPException {
		conn.bind(dn, passwd);
	}

	public void bind(int version, String dn, String passwd) throws LDAPException {
		conn.bind(version, dn, passwd);
	}

	public void bind(String dn, String passwd, LDAPConstraints cons) throws LDAPException {
		conn.bind(dn, passwd, cons);
	}

	public void bind(int version, String dn, String passwd, LDAPConstraints cons) throws LDAPException {
		conn.bind(version, dn, passwd, cons);
	}

	public void bind(int version, String dn, byte[] passwd) throws LDAPException {
		conn.bind(version, dn, passwd);
	}

	public void bind(int version, String dn, byte[] passwd, LDAPConstraints cons) throws LDAPException {
		conn.bind(version, dn, passwd, cons);
	}

	public LDAPResponseQueue bind(int version, String dn, byte[] passwd, LDAPResponseQueue queue) throws LDAPException {
		return conn.bind(version, dn, passwd, queue);
	}

	public LDAPResponseQueue bind(int version, String dn, byte[] passwd, LDAPResponseQueue queue, LDAPConstraints cons)
			throws LDAPException {
		return conn.bind(version, dn, passwd, queue, cons);
	}

	public void bind(String dn, String authzId, Map props, Object cbh) throws LDAPException {
		conn.bind(dn, authzId, props, cbh);
	}

	public void bind(String dn, String authzId, Map props, Object cbh, LDAPConstraints cons) throws LDAPException {
		conn.bind(dn, authzId, props, cbh, cons);
	}

	public void bind(String dn, String authzId, String[] mechanisms, Map props, Object cbh) throws LDAPException {
		conn.bind(dn, authzId, mechanisms, props, cbh);
	}

	public void bind(String dn, String authzId, String[] mechanisms, Map props, Object cbh, LDAPConstraints cons)
			throws LDAPException {
		conn.bind(dn, authzId, mechanisms, props, cbh, cons);
	}

	public boolean compare(String dn, LDAPAttribute attr) throws LDAPException {
		return conn.compare(dn, attr);
	}

	public boolean compare(String dn, LDAPAttribute attr, LDAPConstraints cons) throws LDAPException {
		return conn.compare(dn, attr, cons);
	}

	public LDAPResponseQueue compare(String dn, LDAPAttribute attr, LDAPResponseQueue queue) throws LDAPException {
		return conn.compare(dn, attr, queue);
	}

	public LDAPResponseQueue compare(String dn, LDAPAttribute attr, LDAPResponseQueue queue, LDAPConstraints cons)
			throws LDAPException {
		return conn.compare(dn, attr, queue, cons);
	}

	public void connect(String host, int port) throws LDAPException {
		conn.connect(host, port);
	}

	public void delete(String dn) throws LDAPException {
		throw new LDAPException("READONLY", 0, "Connection is read only");
	}

	public void delete(String dn, LDAPConstraints cons) throws LDAPException {
		throw new LDAPException("READONLY", 0, "Connection is read only");
	}

	public LDAPResponseQueue delete(String dn, LDAPResponseQueue queue) throws LDAPException {
		throw new LDAPException("READONLY", 0, "Connection is read only");
	}

	public LDAPResponseQueue delete(String dn, LDAPResponseQueue queue, LDAPConstraints cons) throws LDAPException {
		throw new LDAPException("READONLY", 0, "Connection is read only");
	}

	public void disconnect() throws LDAPException {
		conn.disconnect();
	}

	public void disconnect(LDAPConstraints cons) throws LDAPException {
		conn.disconnect(cons);
	}

	public LDAPExtendedResponse extendedOperation(LDAPExtendedOperation op) throws LDAPException {
		return conn.extendedOperation(op);
	}

	public LDAPExtendedResponse extendedOperation(LDAPExtendedOperation op, LDAPConstraints cons) throws LDAPException {
		return conn.extendedOperation(op, cons);
	}

	public LDAPResponseQueue extendedOperation(LDAPExtendedOperation op, LDAPResponseQueue queue) throws LDAPException {
		return conn.extendedOperation(op, queue);
	}

	public LDAPResponseQueue extendedOperation(LDAPExtendedOperation op, LDAPConstraints cons, LDAPResponseQueue queue)
			throws LDAPException {
		return conn.extendedOperation(op, cons, queue);
	}

	public LDAPControl[] getResponseControls() {
		return conn.getResponseControls();
	}

	public void modify(String dn, LDAPModification mod) throws LDAPException {
		throw new LDAPException("READONLY", 0, "Connection is read only");
	}

	public void modify(String dn, LDAPModification mod, LDAPConstraints cons) throws LDAPException {
		throw new LDAPException("READONLY", 0, "Connection is read only");
	}

	public void modify(String dn, LDAPModification[] mods) throws LDAPException {
		throw new LDAPException("READONLY", 0, "Connection is read only");
	}

	public void modify(String dn, LDAPModification[] mods, LDAPConstraints cons) throws LDAPException {
		throw new LDAPException("READONLY", 0, "Connection is read only");
	}

	public LDAPResponseQueue modify(String dn, LDAPModification mod, LDAPResponseQueue queue) throws LDAPException {
		throw new LDAPException("READONLY", 0, "Connection is read only");
	}

	public LDAPResponseQueue modify(String dn, LDAPModification mod, LDAPResponseQueue queue, LDAPConstraints cons)
			throws LDAPException {
		throw new LDAPException("READONLY", 0, "Connection is read only");
	}

	public LDAPResponseQueue modify(String dn, LDAPModification[] mods, LDAPResponseQueue queue) throws LDAPException {
		throw new LDAPException("READONLY", 0, "Connection is read only");
	}

	public LDAPResponseQueue modify(String dn, LDAPModification[] mods, LDAPResponseQueue queue, LDAPConstraints cons)
			throws LDAPException {
		throw new LDAPException("READONLY", 0, "Connection is read only");
	}

	public LDAPEntry read(String dn) throws LDAPException {
		return conn.read(dn);
	}

	public LDAPEntry read(String dn, LDAPSearchConstraints cons) throws LDAPException {
		return conn.read(dn, cons);
	}

	public LDAPEntry read(String dn, String[] attrs) throws LDAPException {
		return conn.read(dn, attrs);
	}

	public LDAPEntry read(String dn, String[] attrs, LDAPSearchConstraints cons) throws LDAPException {
		return conn.read(dn, attrs, cons);
	}

	public void rename(String dn, String newRdn, boolean deleteOldRdn) throws LDAPException {
		throw new LDAPException("READONLY", 0, "Connection is read only");
	}

	public void rename(String dn, String newRdn, boolean deleteOldRdn, LDAPConstraints cons) throws LDAPException {
		throw new LDAPException("READONLY", 0, "Connection is read only");
	}

	public void rename(String dn, String newRdn, String newParentdn, boolean deleteOldRdn) throws LDAPException {
		throw new LDAPException("READONLY", 0, "Connection is read only");
	}

	public void rename(String dn, String newRdn, String newParentdn, boolean deleteOldRdn, LDAPConstraints cons)
			throws LDAPException {
		throw new LDAPException("READONLY", 0, "Connection is read only");
	}

	public LDAPResponseQueue rename(String dn, String newRdn, boolean deleteOldRdn, LDAPResponseQueue queue)
			throws LDAPException {
		throw new LDAPException("READONLY", 0, "Connection is read only");
	}

	public LDAPResponseQueue rename(String dn, String newRdn, boolean deleteOldRdn, LDAPResponseQueue queue,
			LDAPConstraints cons) throws LDAPException {
		throw new LDAPException("READONLY", 0, "Connection is read only");
	}

	public LDAPResponseQueue rename(String dn, String newRdn, String newParentdn, boolean deleteOldRdn,
			LDAPResponseQueue queue) throws LDAPException {
		throw new LDAPException("READONLY", 0, "Connection is read only");
	}

	public LDAPResponseQueue rename(String dn, String newRdn, String newParentdn, boolean deleteOldRdn,
			LDAPResponseQueue queue, LDAPConstraints cons) throws LDAPException {
		throw new LDAPException("READONLY", 0, "Connection is read only");
	}

	public LDAPSearchResults search(String base, int scope, String filter, String[] attrs, boolean typesOnly)
			throws LDAPException {
		return conn.search(base, scope, filter, attrs, typesOnly);
	}

	public LDAPSearchResults search(String base, int scope, String filter, String[] attrs, boolean typesOnly,
			LDAPSearchConstraints cons) throws LDAPException {
		return conn.search(base, scope, filter, attrs, typesOnly, cons);
	}

	public LDAPSearchQueue search(String base, int scope, String filter, String[] attrs, boolean typesOnly,
			LDAPSearchQueue queue) throws LDAPException {
		return conn.search(base, scope, filter, attrs, typesOnly, queue);
	}

	public LDAPSearchQueue search(String base, int scope, String filter, String[] attrs, boolean typesOnly,
			LDAPSearchQueue queue, LDAPSearchConstraints cons) throws LDAPException {
		return conn.search(base, scope, filter, attrs, typesOnly, queue, cons);
	}

	public LDAPMessageQueue sendRequest(LDAPMessage request, LDAPMessageQueue queue) throws LDAPException {
		return conn.sendRequest(request, queue);
	}

	public LDAPMessageQueue sendRequest(LDAPMessage request, LDAPMessageQueue queue, LDAPConstraints cons)
			throws LDAPException {
		return conn.sendRequest(request, queue, cons);
	}

	public LDAPSchema fetchSchema(String schemaDN) throws LDAPException {
		return conn.fetchSchema(schemaDN);
	}

	public String getSchemaDN() throws LDAPException {
		return conn.getSchemaDN();
	}

	public String getSchemaDN(String dn) throws LDAPException {
		return conn.getSchemaDN(dn);
	}

}
