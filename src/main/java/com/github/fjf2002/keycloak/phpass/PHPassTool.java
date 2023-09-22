package com.github.fjf2002.keycloak.phpass;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Acknowledgements to
 * 
 * * http://www.openwall.com/phpass/
 *
 * * https://github.com/Wolf480pl/PHPass/
 * 
 * Copyright (c) 2012-2013 Wolf480pl (wolf480@interia.pl)
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
public final class PHPassTool {

	private static String itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

	private static int MAX_HASH_LENGTH = 55;

	private PHPassTool() {
	}

	private static String encode64(byte[] src, int count) {
		int i, value;
		String output = "";
		i = 0;

		if (src.length < count) {
			byte[] t = new byte[count];
			System.arraycopy(src, 0, t, 0, src.length);
			Arrays.fill(t, src.length, count - 1, (byte) 0);
			src = t;
		}

		do {
			value = src[i] & 0xff;
			++i;
			output += itoa64.charAt(value & 63);
			if (i < count) {
				value |= (src[i] & 0xff) << 8;
			}
			output += itoa64.charAt((value >> 6) & 63);
			if (i++ >= count) {
				break;
			}
			if (i < count) {
				value |= (src[i] & 0xff) << 16;
			}
			output += itoa64.charAt((value >> 12) & 63);
			if (i++ >= count) {
				break;
			}
			output += itoa64.charAt((value >> 18) & 63);
		} while (i < count);
		return output;
	}

	public static String generateSettings(int iterationsLogBase2) {
		String output = "$S$";
		// Convert the log base2 iteration count to a base64 character representation
		output += itoa64.charAt(iterationsLogBase2);
		// Generate the 6 random bytes of salt for a portable phpass hash
		byte[] saltyBytes = new byte[6];
		try {
			SecureRandom.getInstanceStrong().nextBytes(saltyBytes);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
		output += encode64(saltyBytes, 6);
		return output;
	}

	public static String hash(String password, String setting) {
		if (((setting.length() < 2) ? setting : setting.substring(0, 2)).equalsIgnoreCase("*0")) {
			throw new RuntimeException("Not a PHPass hash");
		}
		String id = (setting.length() < 3) ? setting : setting.substring(0, 3);
		if (!(id.equals("$P$") || id.equals("$H$") || id.equals("$S$"))) {
			throw new RuntimeException("Not a PHPass hash");
		}
		String alg = "MD5";
		if (id.equals("$S$")) {
			alg = "SHA-512";
		}
		int countLog2 = itoa64.indexOf(setting.charAt(3));
		if (countLog2 < 7 || countLog2 > 30) {
			throw new RuntimeException("Wrong PHPass hash chatAt(3) value.");
		}
		int count = 1 << countLog2;
		final String salt = setting.substring(4, 4 + 8);
		if (salt.length() != 8) {
			throw new RuntimeException("Wrong salt length.");
		}

		try {
			final MessageDigest md = MessageDigest.getInstance(alg);
			final byte[] pass = stringToUtf8Bytes(password);
			byte[] hash = md.digest(stringToUtf8Bytes(salt + password));
			do {
				byte[] t = new byte[hash.length + pass.length];
				System.arraycopy(hash, 0, t, 0, hash.length);
				System.arraycopy(pass, 0, t, hash.length, pass.length);
				hash = md.digest(t);
			} while (--count > 0);
			String output = setting.substring(0, 12);
			final int len = hash.length;
			output += encode64(hash, len);
			if (output.length() > MAX_HASH_LENGTH) {
				output = output.substring(0, MAX_HASH_LENGTH);
			}
			return output;
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}

	}

	private static byte[] stringToUtf8Bytes(String string) {
		return string.getBytes(StandardCharsets.UTF_8);
	}

	public static boolean checkPassword(String password, String storedHash) {
		return hash(password, storedHash).equals(storedHash);
	}
}
