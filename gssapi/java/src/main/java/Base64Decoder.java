/* (c) 2009, Quest Software, Inc. All rights reserved. */

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

/**
 * Decodes BASE64 encoded data.
 * <p>
 * For simple use, see {{@link #decode(byte[])}.
 * <p>
 * For streaming data, use the {@link #feed(byte[])} method with a target output stream:
 * <pre>
 *  Base64Decoder decoder = new Base64Decoder(someOutputStream);
 *  decoder.feed(encodedDataBytes);
 *  decoder.feed(moreEncodedDataBytes);
 *  decoder.end();
 * </pre>
 */
public class Base64Decoder {

	private final byte[] buffer = new byte[4];
	private int position;
	private int padding;
	private final OutputStream out;
	
	private static final byte[] decodeTable = {
	    -1,-1,-1,-1,-1,-1,-1,-1,   /* -1: invalid */
	    -1,-2,-2,-2,-2,-2,-1,-1,   /* -2: whitespace */
	    -1,-1,-1,-1,-1,-1,-1,-1,   /* -3: = */
	    -1,-1,-1,-1,-1,-1,-1,-1,   /* 0..63: base64 digit */
	    -2,-1,-1,-1,-1,-1,-1,-1,
	    -1,-1,-1,62,-1,-1,-1,63,
	    52,53,54,55,56,57,58,59,
	    60,61,-1,-1,-1,-3,-1,-1,
	    -1, 0, 1, 2, 3, 4, 5, 6,
	     7, 8, 9,10,11,12,13,14,
	    15,16,17,18,19,20,21,22,
	    23,24,25,-1,-1,-1,-1,-1,
	    -1,26,27,28,29,30,31,32,
	    33,34,35,36,37,38,39,40,
	    41,42,43,44,45,46,47,48,
	    49,50,51,-1,-1,-1,-1,-1
	};
	private static final byte INVALID = -1;
	private static final byte WHITESPACE = -2;
	private static final byte PADDING = -3;
	
	protected static final int EOF = -1;
	protected static final int CONTINUE = -2;
	protected static final int TERMINAL = -3;
	
	/**
	 * Constructs a new BASE64 decoder.
	 * @param out Where decoded bytes are written
	 */
	public Base64Decoder(OutputStream out) {
		this.out = out;
	}
	
	/**
	 * Decodes the partial BASE64 data and writes it to the output.
	 * @param b  partial BASE64 data
	 */
	public void feed(byte[] b) throws IOException {
		feed(b, 0, b.length);
	}

	/**
	 * Decodes the partial BASE64 data and writes it to the output.
	 * @param b  partial BASE64 data
	 * @param off offset into b to decode from
	 * @param len number of bytes of data to decode from b
	 */
	public void feed(byte[] b, int off, int len) throws IOException {
		while (len-- > 0) 
			feed(b[off++] & 0xff);
	}
	
	/** Decodes one byte of BASE64 encoded data, and possibly writes data to the output.
	 * @param b the next byte of the BASE64 encoded data
	 * @throws IOException
	 */
	public void feed(int b) throws IOException {
		int ch = decode1(b);
		if (ch >= 0)
			out.write(ch);
	}
	
	/**
	 * Signals the end of input to the decoder.
	 * @throws IOException if there was incomplete BASE64 data
	 */
	public void end() throws IOException {
		decode1(-1);
	}
	
	/**
	 * Decodes a single input byte.
	 * Returns a non-negative byte, or one of the values EOF, CONTINUE or TERMINAL.
	 * A terminal usually indicates no more data follows.
	 */
	protected int decode1(int ch) throws IOException {
		if (ch == -1) {
			if (position != 0)
				throw new IOException("Unexpected end of BASE64 stream");
			return EOF;
		}
		byte digit = ch < decodeTable.length ? decodeTable[ch] : INVALID;
		if (digit == WHITESPACE)
			return CONTINUE;
		if (digit == INVALID || 
				(digit == PADDING && position < 2) ||
				(digit >= 0 && padding > 0))
			throw new IOException("Invalid BASE64 input at 0x" + Integer.toHexString(ch));
		if (digit == PADDING) {
			padding++;
			digit = 0;
		}
		buffer[position++] = digit;
		switch (position) {
		case 2: /* 8+4 bits */
			return (buffer[0] << 2 | buffer[1] >> 4) & 0xff;
		case 3: /* 8+8+2 bits */
			if (padding == 0)
				return (buffer[1] << 4 | buffer[2] >> 2) & 0xff;
			break;
		case 4: /* 8+8+8 bits */
			position = 0;
			if (padding > 0) {
				padding = 0;
				return TERMINAL;
			}
			return (buffer[2] << 6 | buffer[3]) & 0xff;
		}
		return CONTINUE;
	}

	/** Decodes BASE64 data. */
	public static byte[] decode(byte[] data) throws IOException {
		ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		Base64Decoder decoder = new Base64Decoder(buffer);
		decoder.feed(data);
		decoder.end();
		return buffer.toByteArray();
	}

	/**
	 * Returns an OutputStream interface to this decoder instance.
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
