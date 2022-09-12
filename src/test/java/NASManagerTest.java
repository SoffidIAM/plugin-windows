import java.io.IOException;

import com.hierynomus.mssmb2.SMB2Dialect;
import com.hierynomus.security.bc.BCSecurityProvider;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.soffid.iam.sync.nas.NASManager;

import es.caib.seycon.ng.comu.Password;

public class NASManagerTest {
	public static void main (String args[]) throws Exception {
		if (true) {
			NASManager m;

			m = new NASManager("AD", "ad.bubu.lab", "Administrator", new Password("Test70."));
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
			Connection adConnection = smbClient.connect("10.129.120.13");
			final AuthenticationContext adAuthenticationContext = new AuthenticationContext(
					"Administrador", "Test70.".toCharArray(), "10.129.120.13");
			Session adSession = adConnection.authenticate(adAuthenticationContext);
	
			
			NASManager m;
	
 			m = new NASManager("win-uq9f24f4d4h", "10.129.120.13", "Administrador", new Password("Test70."));
			
			m.createFolder("//10.129.120.13/c$/test-folder4", null);
			
		}
	}
}
