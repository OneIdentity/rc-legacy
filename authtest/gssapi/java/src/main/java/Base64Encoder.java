/* (c) 2009, Quest Software, Inc. All rights reserved. */

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

/** Encodes data into BASE64 */
public class Base64Encoder {

	private final int buffer[] = new int[3];
	private int length;
	private static final int encodeTab[] = {
		'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
		'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z',
		'0','1','2','3','4','5','6','7','8','9','+','/'
	};
	private final OutputStream out;
	
	/** Constructs a new encoding output stream. */
	public Base64Encoder(OutputStream out) {
		this.out = out;
	}
	
	public void feed(int b) throws IOException {
		buffer[length++] = b;
		switch (length) {
		case 1:
			out.write(encodeTab[(buffer[0] & 0xfc) >> 2 & 0x3f]);
			break;
		case 2:
			out.write(encodeTab[(buffer[0] << 4 | (buffer[1] & 0xf0) >> 4) & 0x3f]);
			break;
		case 3:
			out.write(encodeTab[(buffer[1] << 2 | (buffer[2] & 0xc0) >> 6) & 0x3f]);
			out.write(encodeTab[buffer[2] & 0x3f]);
			length = 0;
			break;
		}
	}
	
	public void feed(byte[] b) throws IOException {
		feed(b, 0, b.length);
	}
	
	public void feed(byte[] b, int off, int len) throws IOException {
		while (len-- > 0)
			feed(b[off++] & 0xff);
	}

	public void end() throws IOException {
		switch (length) {
		case 1:
			out.write(encodeTab[(buffer[0] << 4) & 0x3f]);
			out.write('=');
			out.write('=');
			break;
		case 2:
			out.write(encodeTab[(buffer[1] << 2) & 0x3f]);
			out.write('=');
			break;
		}
		length = 0;
	}
	
	public static byte[] encode(byte[] data) throws IOException {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		Base64Encoder encoder = new Base64Encoder(out);
		encoder.feed(data);
		encoder.end();
		return out.toByteArray();
	}
	
	/**
	 * Returns an OutputStream interface to this encoder instance.
	 */
	public OutputStream asOutputStream() {
		return new OutputStream() {
			@Override
			public void write(int b) throws IOException { feed(b); }
			@Override
			public void close() throws IOException { end(); }
		};
	}

}
