package com.soffid.iam.sync.agent;

public class GUIDParser {
	   public static String format(byte[] objectGUID) {
	        StringBuilder displayStr = new StringBuilder();

	        displayStr.append(prefixZeros((int) objectGUID[3] & 0xFF));
	        displayStr.append(prefixZeros((int) objectGUID[2] & 0xFF));
	        displayStr.append(prefixZeros((int) objectGUID[1] & 0xFF));
	        displayStr.append(prefixZeros((int) objectGUID[0] & 0xFF));
	        displayStr.append("-");
	        displayStr.append(prefixZeros((int) objectGUID[5] & 0xFF));
	        displayStr.append(prefixZeros((int) objectGUID[4] & 0xFF));
	        displayStr.append("-");
	        displayStr.append(prefixZeros((int) objectGUID[7] & 0xFF));
	        displayStr.append(prefixZeros((int) objectGUID[6] & 0xFF));
	        displayStr.append("-");
	        displayStr.append(prefixZeros((int) objectGUID[8] & 0xFF));
	        displayStr.append(prefixZeros((int) objectGUID[9] & 0xFF));
	        displayStr.append("-");
	        displayStr.append(prefixZeros((int) objectGUID[10] & 0xFF));
	        displayStr.append(prefixZeros((int) objectGUID[11] & 0xFF));
	        displayStr.append(prefixZeros((int) objectGUID[12] & 0xFF));
	        displayStr.append(prefixZeros((int) objectGUID[13] & 0xFF));
	        displayStr.append(prefixZeros((int) objectGUID[14] & 0xFF));
	        displayStr.append(prefixZeros((int) objectGUID[15] & 0xFF));

	        return displayStr.toString();
	    }

	    private static String prefixZeros(int value) {
	        if (value <= 0xF) {
	            StringBuilder sb = new StringBuilder("0");
	            sb.append(Integer.toHexString(value));

	            return sb.toString();
	        } else {
	            return Integer.toHexString(value);
	        }
	    }

		public static byte[] parseGuid(String s) {
			long parts[] = new long [5];
			int i = 0;
			for ( String ss: s.split("-"))
			{
				parts[i++] = Long.parseLong(ss, 16);
			}
			byte r[] = new byte[16];
			i = 0;
			r[i++] = (byte) ((parts[0] >> 0) & 0xff);
			r[i++] = (byte) ((parts[0] >> 8) & 0xff);
			r[i++] = (byte) ((parts[0] >> 16) & 0xff);
			r[i++] = (byte) ((parts[0] >> 24) & 0xff);

			r[i++] = (byte) ((parts[1] >> 0) & 0xff);
			r[i++] = (byte) ((parts[1] >> 8) & 0xff);

			r[i++] = (byte) ((parts[2] >> 0) & 0xff);
			r[i++] = (byte) ((parts[2] >> 8) & 0xff);

			r[i++] = (byte) ((parts[3] >> 8) & 0xff);
			r[i++] = (byte) ((parts[3] >> 0) & 0xff);

			r[i++] = (byte) ((parts[4] >> 40) & 0xff);
			r[i++] = (byte) ((parts[4] >> 32) & 0xff);
			r[i++] = (byte) ((parts[4] >> 24) & 0xff);
			r[i++] = (byte) ((parts[4] >> 16) & 0xff);
			r[i++] = (byte) ((parts[4] >> 8) & 0xff);
			r[i++] = (byte) ((parts[4] >> 0) & 0xff);

			return r;
		}
}
