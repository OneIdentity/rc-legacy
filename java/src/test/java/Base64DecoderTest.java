import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

import junit.framework.TestCase;

public class Base64DecoderTest extends TestCase {

	/* Returns the decoded text */
	static byte[] decode(final byte[] input) throws Exception {
		return Base64Decoder.decode(input);
	}
	
	static byte[] decode(final String input) throws Exception {
		return decode(input.getBytes("UTF-8"));
	}
	
	/** Decodes something and expects an IOException */
	static void assertDecodeError(final byte[] input) throws Exception {
		try {
			byte[] output = decode(input);
			fail("expected IOException from " + toString(input) + " but got " + toString(output));
		} catch (IOException e) {
			/* pass */
		}
	}
	
	static void assertDecodeError(final String input) throws Exception {
		assertDecodeError(input.getBytes("UTF-8"));
	}
	
	public void testPartial() throws Exception {
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		Base64Decoder decoder = new Base64Decoder(bos);
		decoder.feed('A');
		decoder.feed(new byte[] { 0, '.', 'Q', '#', 0, 0}, 2, 1);
		decoder.feed(new byte[] { 'I', 'D' });
		decoder.end();
		assertEquals(new byte[] { 1, 2, 3 }, bos.toByteArray());
	}

	public void testEmpty() throws Exception {
		assertEquals(new byte[] {}, decode(new byte[] {}));
	}
	
	public void testSingleZero() throws Exception {
		assertEquals(new byte[] {0}, decode(new byte[] {'A','A','=','='}));
	}

	public void testSingleOne() throws Exception {
		assertEquals(new byte[] {1}, decode(new byte[] {'A','Q','=','='}));
	}
	
	public void testTwo() throws Exception {
		assertEquals(new byte[] {1,2}, decode(new byte[] {'A','Q','I','='}));
	}

	public void testThree() throws Exception {
		assertEquals(new byte[] {1,2,3}, decode(new byte[] {'A','Q','I','D'}));
	}

	public void testFour() throws Exception {
		assertEquals(new byte[] {1,2,3,4}, decode("AQIDBA=="));
	}
	
	public void testShortError() throws Exception {
		assertDecodeError(new byte[]{'A'});
		assertDecodeError("AB");
		assertDecodeError("ABC");
	}

	public void testBadPadding() throws Exception {
		assertDecodeError("=");
		assertDecodeError("==");
		assertDecodeError("===");
		assertDecodeError("====");
		assertDecodeError("A=");
		assertDecodeError("A==");
		assertDecodeError("A===");
		assertDecodeError("AB=X");
		assertDecodeError("AB=");
	}
	
	public void testWhitespace() throws Exception {
		assertEquals(new byte[] {}, decode(" "));
		assertEquals(new byte[] {}, decode("  "));
		assertEquals(new byte[] {}, decode("   "));
		assertEquals(new byte[] {}, decode("    "));
		assertEquals(new byte[] {}, decode("\n\r\t "));
		assertEquals(new byte[] {1,2,3}, decode(" A Q I D "));
		assertEquals(new byte[] {1,2,3,4}, decode(" A Q I D B A = = "));
		assertDecodeError("          ABC");
		assertDecodeError("          .");
	}
	
	public void testBadChars() throws Exception {
		assertDecodeError(".");
		assertDecodeError("_");
		assertDecodeError(new byte[] { 0 });
	}
	
	public void testBinary() throws Exception {
		assertEquals(new byte[] {0x5a,(byte)0xa5,0x5a,(byte)0xa5,0x5a,(byte)0xa5}, decode("WqVapVql"));
		assertEquals(new byte[] {-1,-1,-1}, decode("////"));
	}

	/** Helper function that asserts the equality of two byte arrays */
	static public void assertEquals(byte[] expected, byte[] actual) {
		if (!Arrays.equals(expected, actual)) 
			failNotEquals(null, toString(expected), toString(actual));
	}
	
	/** Returns the string form of a byte array, as an escaped string */
	static String toString(byte[] array) {
		if (array == null)
			return "(null)";
		StringBuffer buf = new StringBuffer();
		for (byte b : array) 
			if (b == '\\')
				buf.append("\\\\");
			else if (b == '\r')
				buf.append("\\r");
			else if (b == '\n')
				buf.append("\\n");
			else if (b == '\t')
				buf.append("\\t");
			else if (b < 32 || b >= 127)
				buf.append("\\x" + Integer.toHexString(b & 0xff));
			else
				buf.append((char)b);
		return buf.toString();
	}
	
}
