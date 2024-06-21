import java.io.IOException;
import java.util.HashMap;

import com.hierynomus.mssmb2.SMB2Dialect;
import com.hierynomus.security.bc.BCSecurityProvider;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.rapid7.client.dcerpc.mssamr.dto.ServerHandle;
import com.rapid7.client.dcerpc.transport.RPCTransport;
import com.rapid7.client.dcerpc.transport.SMBTransportFactories;
import com.soffid.iam.sync.nas.NASManager;
import com.soffid.msrpc.samr.SamrService;

import es.caib.seycon.ng.comu.Password;

public class NASManagerTest {
	public static void main (String args[]) throws Exception {
		if (false) {
			NASManager m;

			m = new NASManager("AD", "ad.bubu.lab", "Administrator", new Password("Test70."), new HashMap<>(),
					true);
			m.createFolder("//ad.bubu.lab/c$/test-folder", null);
			
			m.addAcl("//ad.bubu.lab/c$/test-folder", "ppig", "GENERIC_ALL", "CONTAINER_INHERIT_ACE OBJECT_INHERIT_ACE", null);

		} else {
			SmbConfig config = SmbConfig.builder()
		            .withDialects( 
		            		SMB2Dialect.SMB_2_0_2, SMB2Dialect.SMB_2_1
//		            		SMB2Dialect.SMB_3_0, SMB2Dialect.SMB_3_0_2, SMB2Dialect.SMB_3_1_1
		            		)
		            .withSecurityProvider(new BCSecurityProvider())
		            .build();
	
			SMBClient smbClient = new SMBClient(config );
			Connection adConnection = smbClient.connect("192.168.133.155");
			final AuthenticationContext adAuthenticationContext = new AuthenticationContext(
					"Administrator", "geheim01".toCharArray(), "192.168.133.155");
			Session adSession = adConnection.authenticate(adAuthenticationContext);
			String s = adSession.getConnection().getConnectionInfo().getNetBiosName();
			System.out.println(s);
		}
	}
}
