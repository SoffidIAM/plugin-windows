import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;

import javax.net.ssl.SSLSocketFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.novell.ldap.LDAPJSSESecureSocketFactory;

class DebugLDAPSecureSocketFactory2 extends LDAPJSSESecureSocketFactory {
	Logger log = LoggerFactory.getLogger(getClass());

	public Logger getLog() {
		return log;
	}

	public void setLog(Logger log2) {
		this.log = log2;
	}

	public DebugLDAPSecureSocketFactory2(
			SSLSocketFactory socketFactory) {
		super (socketFactory);
	}

	@Override
	public Socket createSocket(String host, int port) throws IOException,
			UnknownHostException {
		System.out.println("connecting to "+host);
		try {
			Socket socket = super.createSocket(host, port);
			System.out.println("Connected to "+host+":"+port);
			return socket;
		} catch (IOException e) {
			System.out.println("Error connecting to "+host+":"+port+" "+e.toString());
			throw e;
		}
	}

}