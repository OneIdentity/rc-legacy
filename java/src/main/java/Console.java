/* (c) 2009, Quest Software, Inc. All rights reserved. */

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;

/**
 * This class manages user input/output, so that the GSS tokens can be displayed and entered.
 * Typically, the user will run this on one console and cut & paste between it and another console. 
 */
public class Console {
	
	private final BufferedReader in;
	private final PrintStream out;
	
	public Console() {
		this(System.in, System.out);
	}
	
	public Console(InputStream in, OutputStream out) {
		this.in = new BufferedReader(new InputStreamReader(in));
		this.out = out instanceof PrintStream ? (PrintStream)out : new PrintStream(out);
	}
	
	/** Prompts for, reads a BASE64 encoded token terminated with a '.', and returns the decoded token */
	public byte[] readToken() throws IOException {
		StringBuffer buffer = new StringBuffer();
		out.print("input: ");
		out.flush();
		while (true) {
			String line = in.readLine();
			if (line == null)
				break;
			int pos = line.indexOf('.');
			if (pos == -1)
				buffer.append(line);
			else {
				buffer.append(line.substring(0, pos));
				break;
			}
		}
		return Base64Decoder.decode(buffer.toString().getBytes("UTF-8"));
	}
	
	/** Writes the token, encoded as BASE64, and terminated with a dot, to standard output */
	public void writeToken(byte[] token) throws IOException {
		out.print("output: ");
		out.write(Base64Encoder.encode(token));
		out.println(".");
		out.flush();
	}
	
	public void println(String msg) { out.println(msg);	}
	public void println() { out.println(); }
	public void print(String msg) { out.print(msg); }
	
}
