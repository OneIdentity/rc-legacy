/* (c) 2009, Quest Software, Inc. All rights reserved. */

import java.io.PrintStream;
import java.security.Provider;
import java.security.Security;
import java.util.List;
import java.util.Vector;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;


public class GSSUtil {

	/**
	 * Returns a string representing the flags of a GSS Context
	 */
	public static String getFlagsFrom(GSSContext context) {
		List<String> flags = new Vector<String>();
		if (context.getMutualAuthState())
			flags.add("mutual");
		if (context.getReplayDetState())
			flags.add("replay");
		if (context.getSequenceDetState())
			flags.add("sequence");
		if (context.getConfState())
			flags.add("conf");
		if (context.getIntegState())
			flags.add("integ");
		if (context.getAnonymityState())
			flags.add("anon");
		StringBuffer buffer = new StringBuffer();
		for (String flag : flags) {
			if (buffer.length() > 0)
				buffer.append(",");
			buffer.append(flag);
		}
		return buffer.toString();
	}

	/** Applies the request flags to the GSS Context. */
	public static void applyReqFlagsTo(String reqFlags, GSSContext context) throws Exception {
		if (reqFlags == null || "".equals(reqFlags))
			return;
		String[] flagArray = reqFlags.split(",");
		for (String flag : flagArray) {
			if ("deleg".equals(flag))
				context.requestCredDeleg(true);
			else if ("mutual".equals(flag))
				context.requestMutualAuth(true);
			else if ("replay".equals(flag))
				context.requestReplayDet(true);
			else if ("sequence".equals(flag))
				context.requestSequenceDet(true);
			else if ("conf".equals(flag))
				context.requestConf(true);
			else if ("integ".equals(flag))
				context.requestInteg(true);
			else if ("anon".equals(flag))
				context.requestAnonymity(true);
			else
				throw new IllegalArgumentException("Unknown flag: " + flag);
		}
	}

	private static final Oid NT_KRB5_PRINICPAL_NAME = makeOid("1.2.840.113554.1.2.2.1");
	
	/* Make an OID, converting format exceptions into a runtime exception.
	 * This is so the KRB5 OID can be statically initialized. */
	private static Oid makeOid(String oid) {
		try { return new Oid(oid); }
		catch (GSSException e) { throw new RuntimeException("Cannot initialize KRB5 OID", e); }
	}

	/**
	 * Converts a name type string into an OID.
	 * Understands dotted OIDs, and the strings "none", "hostbased" and "krb5"
	 */
	public static Oid nameTypeToOid(String nameType) throws Exception {
		if ("none".equals(nameType))
			return null;
		if ("hostbased".equals(nameType))
			return GSSName.NT_HOSTBASED_SERVICE;
		if ("krb5".equals(nameType))
			return NT_KRB5_PRINICPAL_NAME;
		return new Oid(nameType);
	}

	/**
	 * Converts a name type OID into a string, suitable for use with {@link #nameTypeToOid(String)}.
	 */
	public static String nameTypeToString(Oid oid) {
		if (oid == null)
			return "none";
		if (GSSName.NT_HOSTBASED_SERVICE.equals(oid))
			return "hostbased";
		if (NT_KRB5_PRINICPAL_NAME.equals(oid))
			return "krb5";
		return oid.toString();
	}
	
	public static void printProviders(PrintStream out) {
	    out.println("Security Providers -");
	    Provider[] providers = Security.getProviders();
	    for (int i = 0; i < providers.length; i++) {
	      out.println("  " + providers[i]);
	    }
	}

}
