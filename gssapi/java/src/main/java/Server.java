/* (c) 2009, Quest Software, Inc. All rights reserved. */

import java.util.Properties;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.MessageProp;
import org.ietf.jgss.Oid;

/**
 * GSS server
 * @see http://java.sun.com/j2se/1.5.0/docs/guide/security/jgss/tutorials/Troubleshooting.html
 *
 */
public class Server {
	private static final byte[] SERVER_MESSAGE = "I am the Java server".getBytes();
	
	/* Indicates confidentiality required in wrap() */
	private boolean confReq;
	
	/** Service name, or null for default */
	private String serviceName; 
	
	/** The name type of the serviceName */
	private Oid serviceNameType;
	
	private GSSManager manager;
	private Console console;
	
	public static void main(String[] args) throws Exception {
		Server server = new Server();
		server.load(System.getProperties());

		GSSUtil.printProviders(System.out);

		server.run();
	}
	
	public Server() {
		setConsole(new Console());
		setManager(GSSManager.getInstance());
	}
	
	public void setConsole(Console console) {
		this.console = console;
	}
	public void setManager(GSSManager manager) {
		this.manager = manager;
	}
	public void setServiceName(String serviceName) {
		this.serviceName = serviceName;
	}
	
	public void load(Properties properties) throws Exception {
		confReq = Boolean.parseBoolean(properties.getProperty("confReq", Boolean.toString(confReq)));
		serviceNameType = GSSUtil.nameTypeToOid(properties.getProperty("serviceNameType",	GSSUtil.nameTypeToString(serviceNameType)));
		serviceName = properties.getProperty("serviceName", serviceName);
	}
	
	public void run() throws Exception {
		GSSCredential creds = null;
		if (serviceName != null) {
			console.println("serviceName = " + serviceName);
			GSSName service = manager.createName(serviceName, serviceNameType);
			creds = manager.createCredential(service, GSSCredential.DEFAULT_LIFETIME, (Oid)null, GSSCredential.ACCEPT_ONLY);
			console.println("   acquired creds for " + creds.getName().toString());
		} else
			console.println("serviceName = null");
		
		GSSContext context = manager.createContext(creds);
		while (!context.isEstablished()) {
			byte[] inputToken = console.readToken();
			byte[] replyToken = context.acceptSecContext(inputToken, 0, inputToken.length);
			if (replyToken != null)
				console.writeToken(replyToken);
		}
		
		console.println("context established");
		console.println("context flags: " + GSSUtil.getFlagsFrom(context));
		console.println("source = " + context.getSrcName().toString());

		/** Documentation says that getDelegCred will return null when there are no creds,
		 *  but it actually throws an exception. So, check for delegstate first. */
		GSSCredential delegCred = null;
		if (context.getCredDelegState())
			delegCred = context.getDelegCred();
		if (delegCred != null) {
			console.println("credentials were delegated:");
			console.println("   name = " + delegCred.getName().toString());
			console.println("   usage = " + delegCred.getUsage());
			console.println("   lifetime = " + delegCred.getRemainingLifetime());
		} else
			console.println("no delegated credentials");
		
		byte[] token;
		
		console.println("Message to client: " + new String(SERVER_MESSAGE, "UTF-8"));
		MessageProp prop = new MessageProp(confReq);
		token = context.wrap(SERVER_MESSAGE, 0, SERVER_MESSAGE.length, prop);
		console.writeToken(token);
		
		token = console.readToken();
		prop = new MessageProp(false);
		byte[] message = context.unwrap(token, 0, token.length, prop);
		console.println("Message from client: " + new String(message, "UTF-8"));
		console.println("  privacy: " + prop.getPrivacy());
		console.println("  qop:     " + prop.getQOP());
		
		context.dispose();
	}
	
}
