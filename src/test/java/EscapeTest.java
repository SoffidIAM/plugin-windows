import com.soffid.iam.sync.agent.CustomizableActiveDirectoryAgent;


public class EscapeTest {

	public static void main (String args[]) {
		String v = "Dirección General (Proyectos)";
		String v2 = CustomizableActiveDirectoryAgent.escapeLDAPSearchFilter(v);
		System.out.println(v2);
	}
}
