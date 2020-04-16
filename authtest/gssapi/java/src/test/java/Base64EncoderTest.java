import java.io.ByteArrayOutputStream;
import java.io.IOException;

import junit.framework.TestCase;


public class Base64EncoderTest extends TestCase {
	
	public void testPartial() throws Exception {
		ByteArrayOutputStream buf = new ByteArrayOutputStream();
		Base64Encoder encoder = new Base64Encoder(buf);
		encoder.feed(1);
		encoder.feed(new byte[] { -1, -1, 2, -1, -1 }, 2, 1);
		encoder.feed(new byte[] { 3 });
		encoder.end();
		assertEquals("AQID", buf.toString("UTF-8"));
	}
	
	public void testEmpty() throws Exception {
		assertEquals("", encode(new byte[] {}));
	}
	
	public void testOne() throws Exception {
		assertEquals("AA==", encode(new byte[] {0}));
		assertEquals("AQ==", encode(new byte[] {1}));
	}
	
	public void testTwo() throws Exception {
		assertEquals("AQI=", encode(new byte[] {1,2}));
	}

	public void testThree() throws Exception {
		assertEquals("AQID", encode(new byte[] {1,2,3}));
	}

	public void testFour() throws Exception {
		assertEquals("AQIDBA==", encode(new byte[] {1,2,3,4}));
	}
	
	public void testFive() throws Exception {
		assertEquals("AQIDBAU=", encode(new byte[] {1,2,3,4,5}));
	}
	
	public void testBinary() throws Exception {
		assertEquals("WqVapVql", encode(new byte[] {0x5a,(byte)0xa5,0x5a,(byte)0xa5,0x5a,(byte)0xa5}));
		assertEquals("////", encode(new byte[] {-1,-1,-1}));
	}
	
	/* Returns the encoded text */
	static String encode(final byte[] input) throws Exception {
		return new String(Base64Encoder.encode(input), "UTF-8");
	}
	
	static void assertEncodeError(final byte[] input) throws Exception {
		try {
			String output = encode(input);
			fail("expected IOException from " + toString(input) + " but got " + toString(output));
		} catch (IOException e) {
			/* pass */
		}
	}
	
	public static String toString(byte[] b) {
		return Base64DecoderTest.toString(b);
	}
	
	public static String toString(String s) {
		return toString(s.getBytes());
	}

}
