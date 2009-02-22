/* (c) 2009, Quest Software, Inc. All rights reserved. */

import java.util.Properties;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.MessageProp;
import org.ietf.jgss.Oid;

/**
 * GSSAPI client test program.
 *
 * To use VAS credentials, define the following system properties:
 * <pre>
 *    -Djava.security.auth.login.config=jaas-krb5.conf 
 *    -Djavax.security.auth.useSubjectCredsOnly=false
 * </pre>
 * You may need to edit the jaas-krb5.conf file for your environment.
 */
public class Client {
	private static byte[] CLIENT_MESSAGE = "I am the Java client".getBytes();
	
	/** Indicates that confidentiality is required in wrap() */
	private boolean confReq;
	/** Flags to request */
	private String reqFlags;
	/** The target name's name type */
	private Oid nameType;
	/** Name of the target service */
	private String target;
	
	private GSSManager manager;
	private Console console;

	public static void main(String[] args) throws Exception {
		if (args.length != 1 || "-?".equals(args[0])) {
			System.err.println("usage: java [options] " + Client.class.getName() + " <target>\n" +
					"\t-DconfReq=<true|false>\n" +
					"\t-DreqFlags=<deleg,mutual,replay,sequence,conf,integ,anon>\n" +
					"\t-DnameType=<none|hostbased|krb5|dotted-oid>\n");
			System.exit(1);
		}
		
		GSSUtil.printProviders(System.out);
		
		Client client = new Client(args[0]);
		client.load(System.getProperties());
		client.run();
	}
	
	public Client(String target) {
		setManager(GSSManager.getInstance());
		setConsole(new Console());	
		setTarget(target);
	}
	
	// Mutators
	public void setManager(GSSManager manager) {
		this.manager = manager;
	}
	public void setConsole(Console console) {
		this.console = console;
	}
	public void setTarget(String target) {
		this.target = target;
	}
	
	public void run() throws Exception {
		GSSName targetName = manager.createName(target, nameType);
		console.println("targetName = " + targetName.toString());
		console.println("targetName type: " + targetName.getStringNameType().toString());
		console.println("request flags = " + reqFlags);
		
		GSSContext context = manager.createContext(targetName, (Oid)null, null, GSSContext.INDEFINITE_LIFETIME);
		GSSUtil.applyReqFlagsTo(reqFlags, context);
		
		byte[] output = context.initSecContext(new byte[0], 0, 0);
		if (output != null)
			console.writeToken(output);
		while (!context.isEstablished()) {
			byte[] input = console.readToken();
			output = context.initSecContext(input, 0, input.length);
			if (output != null)
				console.writeToken(output);
		}
		
		console.println("Context established");
		console.println("  lifetime: " + context.getLifetime());
		console.println("  flags: " + GSSUtil.getFlagsFrom(context));
		
		// Wait for and decode the server message
		byte[] token = console.readToken();
		MessageProp prop = new MessageProp(false);
		byte[] message = context.unwrap(token, 0, token.length, prop); 
		
		console.println("Message from server: \"" + new String(message, "UTF-8") + "\"");
		console.println("  privacy = " + prop.getPrivacy());
		console.println("  qop = " + prop.getQOP());

		prop = new MessageProp(confReq);
		token = context.wrap(CLIENT_MESSAGE, 0, CLIENT_MESSAGE.length, prop);
		console.writeToken(token);
		
		context.dispose();
	}

	/** Configures member variables from the given properties. */
	public void load(Properties properties) throws Exception {
		confReq = Boolean.parseBoolean(properties.getProperty("confReq", Boolean.toString(confReq)));
		reqFlags = properties.getProperty("reqFlags", reqFlags);
		nameType = GSSUtil.nameTypeToOid(properties.getProperty("nameType",	GSSUtil.nameTypeToString(nameType)));	
	}
}
