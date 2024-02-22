package com.soffid.iam.sync.agent;

import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;

import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocketFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.novell.ldap.LDAPJSSESecureSocketFactory;


public class DebugLDAPSecureSocketFactory extends LDAPJSSESecureSocketFactory {
	Logger log = LoggerFactory.getLogger(getClass());

	public Logger getLog() {
		return log;
	}

	public void setLog(Logger log2) {
		this.log = log2;
	}

	public DebugLDAPSecureSocketFactory(
			SSLSocketFactory socketFactory) {
		super (socketFactory);
	}

	@Override
	public Socket createSocket(String host, int port) throws IOException,
			UnknownHostException {
		try {
			Socket socket = super.createSocket(host, port);
			socket.setSoTimeout(60_000); // One minute to get a response
			return socket;
		} catch (IOException e) {
			System.out.println("Error connecting to "+host+":"+port+" "+e.toString());
			throw e;
		}
	}
}
