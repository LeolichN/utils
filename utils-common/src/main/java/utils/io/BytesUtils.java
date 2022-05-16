package utils.io;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;

import org.bouncycastle.util.Arrays;

import utils.ByteSequence;
import utils.Bytes;
import utils.IllegalDataException;

/**
 * 二进制工具类；
 * 
 * @author haiq
 *
 */
public class BytesUtils {

	public static final String DEFAULT_CHARSET = "UTF-8";

	public static final byte[] EMPTY_BYTES = {};

	public static final int MAX_BUFFER_SIZE = 1024 * 1024 * 1024;
	public static final int BUFFER_SIZE = 64;

	public static final byte TRUE_BYTE = 1;

	public static final byte FALSE_BYTE = 0;

	private BytesUtils() {
	}

	/**
	 * 比较指定的两个字节数组是否一致；
	 * <p>
	 * 
	 * 注：要比较的两个数组的长度都为 0 时总是返回 true;
	 * 
	 * @param bytes1 要比较的数组1；
	 * @param bytes2 要比较的数组2；
	 * @return boolean
	 */
	public static boolean equals(byte[] bytes1, byte[] bytes2) {
		if (bytes1 == bytes2) {
			return true;
		}
		if (bytes1 == null || bytes2 == null) {
			return false;
		}
		if (bytes1.length != bytes2.length) {
			return false;
		}
		for (int i = 0; i < bytes1.length; i++) {
			if (bytes1[i] != bytes2[i]) {
				return false;
			}
		}
		return true;
	}

	/**
	 * 验证两个数组中，从指定偏移开始的相同长度的数据是否相等；
	 * <p>
	 * 
	 * 注：<br>
	 * 要比较的两个数组中任意一个的有效长度不满足指定的长度时，返回 false；
	 * 
	 * @param bytes1  要比较的数组1；
	 * @param offset1 数组1的起始偏移量；
	 * @param bytes2  要比较的数组2；
	 * @param offset2 数组2的起始偏移量；
	 * @param length  要比较的数据的长度； 在有效的偏移量前提下，当指定长度为 0 时，总是返回 true;
	 * @return
	 */
	public static boolean equals(byte[] bytes1, int offset1, byte[] bytes2, int offset2, int length) {
		if (bytes1 == bytes2) {
			return true;
		}
		if (bytes1 == null || bytes2 == null) {
			return false;
		}

		// 验证两个数组的有效长度；
		if (bytes1.length >= (offset1 + length) && bytes2.length >= (offset2 + length)) {
			for (int i = 0; i < length; i++) {
				if (bytes1[offset1 + i] != bytes2[offset2 + i]) {
					return false;
				}
			}
			return true;
		}

		return false;
	}

	public static byte[] toBytes(BytesWriter bytesWriter) {
		try {
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			bytesWriter.writeTo(out);
			return out.toByteArray();
		} catch (IOException e) {
			throw new RuntimeIOException(e.getMessage(), e);
		}

	}

	/**
	 * 将输入流的所有内容都读入到字节数组返回； 如果输入流的长度超出 MAX_BUFFER_SIZE 定义的值，则抛出
	 * IllegalArgumentException ;
	 * 
	 * @param in in
	 * @return byte[]
	 */
	public static byte[] copyToBytes(InputStream in) {
		try {
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			byte[] buffer = new byte[BUFFER_SIZE];
			int len = 0;
			long size = 0;
			while ((len = in.read(buffer)) > 0) {
				size += len;
				if (size > MAX_BUFFER_SIZE) {
					throw new IllegalArgumentException(
							"The size of the InputStream exceed the max buffer size [" + MAX_BUFFER_SIZE + "]!");
				}
				out.write(buffer, 0, len);
			}
			return out.toByteArray();
		} catch (IOException e) {
			throw new RuntimeIOException(e.getMessage(), e);
		}
	}

	public static int copy(InputStream in, OutputStream out) throws IOException {
		return copy(in, out, Integer.MAX_VALUE);
	}

	/**
	 * 将输入流复制到输出流；
	 * 
	 * @param in      输入流；
	 * @param out     输出流；
	 * @param maxSize 最大字节大小；
	 * @return 返回实际复制的字节数；
	 * @throws IOException exception
	 */
	public static int copy(InputStream in, OutputStream out, int maxSize) throws IOException {
		byte[] buffer = new byte[BUFFER_SIZE];
		int len = 0;
		int left = maxSize;
		int readLen = buffer.length;
		while (left > 0) {
			readLen = Math.min(left, buffer.length);
			len = in.read(buffer, 0, readLen);
			if (len > 0) {
				out.write(buffer, 0, len);
				left = left - len;
			} else {
				break;
			}
		}
		return maxSize - left;
	}

	/**
	 * 将 int 值转为4字节的二进制数组；
	 * 
	 * @param value value
	 * @return 转换后的二进制数组，高位在前，低位在后；
	 */
	public static byte[] toBytes(int value) {
		byte[] bytes = new byte[4];
		toBytes(value, bytes, 0);
		return bytes;
	}

	public static byte[] toBytes(short value) {
		byte[] bytes = new byte[2];
		toBytes(value, bytes, 0);
		return bytes;
	}

	public static byte[] toBytes(boolean value) {
		return new byte[] { value ? TRUE_BYTE : FALSE_BYTE };
	}

	/**
	 * 将 long 值转为8字节的二进制数组；
	 * 
	 * @param value value
	 * @return 转换后的二进制数组，高位在前，低位在后；
	 */
	public static byte[] toBytes(long value) {
		byte[] bytes = new byte[8];
		toBytes(value, bytes, 0);
		return bytes;
	}

	/**
	 * 将 int 值转为4字节的二进制数组；
	 * 
	 * @param value 要转换的int整数；
	 * @param bytes 要保存转换结果的二进制数组；转换结果将从高位至低位的顺序写入数组从 0 开始的4个元素；
	 */
	public static void toBytes(short value, byte[] bytes) {
		toBytes(value, bytes, 0);
	}

	public static int toBytes(int value, byte[] bytes) {
		return toBytes(value, bytes, 0);
	}

	/**
	 * 将 int 值转为4字节的二进制数组；
	 * <p>
	 * 以“高位在前”的方式转换，即：数值的高位保存在数组地址的低位（Big Endian 模式）；
	 * 
	 * @param value  要转换的int整数；
	 * @param bytes  要保存转换结果的二进制数组；转换结果将从高位至低位的顺序写入数组从 offset 指定位置开始的4个元素；
	 * @param offset 写入转换结果的起始位置；
	 * @return 返回写入的长度；
	 */
	public static int toBytes(int value, byte[] bytes, int offset) {
		return toBytes_BigEndian(value, bytes, offset);
	}

	/**
	 * 将 int 值转为4字节的二进制数组；
	 * <p>
	 * 以“高位在前”的方式转换，即：数值的高位保存在数组地址的低位（Big Endian 模式）；
	 * 
	 * @param value  要转换的int整数；
	 * @param bytes  要保存转换结果的二进制数组；转换结果将从高位至低位的顺序写入数组从 offset 指定位置开始的4个元素；
	 * @param offset 写入转换结果的起始位置；
	 * @return 返回写入的长度；
	 */
	public static int toBytes_BigEndian(int value, byte[] bytes, int offset) {
		bytes[offset] = (byte) ((value >>> 24) & 0x00FF);
		bytes[offset + 1] = (byte) ((value >>> 16) & 0x00FF);
		bytes[offset + 2] = (byte) ((value >>> 8) & 0x00FF);
		bytes[offset + 3] = (byte) (value & 0x00FF);
		return 4;
	}

	/**
	 * 将 int 值转为4字节的二进制数组；
	 * <p>
	 * 以“高位在后”的方式转换，即：数值的高位保存在数组地址的高位（Little Endian 模式）；
	 * 
	 * @param value  要转换的int整数；
	 * @param bytes  要保存转换结果的二进制数组；转换结果将从高位至低位的顺序写入数组从 offset 指定位置开始的4个元素；
	 * @param offset 写入转换结果的起始位置；
	 * @return 返回写入的长度；
	 */
	public static int toBytes_LittleEndian(int value, byte[] bytes, int offset) {
		bytes[offset] = (byte) (value & 0x00FF);
		bytes[offset + 1] = (byte) ((value >>> 8) & 0x00FF);
		bytes[offset + 2] = (byte) ((value >>> 16) & 0x00FF);
		bytes[offset + 3] = (byte) ((value >>> 24) & 0x00FF);
		return 4;
	}

	/**
	 * 将 int 值转为4字节的二进制数组；
	 * <p>
	 * 以“高位在后”的方式转换，即：数值的高位保存在数组地址的高位（Little Endian 模式）；
	 * 
	 * @param value  要转换的int整数；
	 * @param bytes  要保存转换结果的二进制数组；转换结果将从高位至低位的顺序写入数组从 offset 指定位置开始的4个元素；
	 * @param offset 写入转换结果的起始位置；
	 * @return 返回写入的长度；
	 */
	public static int toBytesInReverse(int value, byte[] bytes, int offset) {
		return toBytes_LittleEndian(value, bytes, offset);
	}

	/**
	 * 将 int 值转为4字节的二进制数组；
	 * <p>
	 * 以“高位在后”的方式转换，即：数值的高位保存在数组地址的高位；
	 * 
	 * @param value  要转换的int整数；
	 * @param bytes  要保存转换结果的二进制数组；转换结果将从高位至低位的顺序写入数组从 offset 指定位置开始的4个元素；
	 * @param offset 写入转换结果的起始位置；
	 * @param len    写入长度；必须大于 0 ，小于等于 4；
	 * @return 返回写入的长度；
	 */
	public static int toBytesInReverse(int value, byte[] bytes, int offset, int len) {
		int i = 0;
		int l = len > 4 ? 4 : len;
		for (; i < l; i++) {
			bytes[offset + i] = (byte) ((value >>> (8 * i)) & 0x00FF);
		}

		return i;
	}

	// public static int toBytes(int value, OutputStream out) {
	// try {
	// out.write((value >>> 24) & 0x00FF);
	// out.write((value >>> 16) & 0x00FF);
	// out.write((value >>> 8) & 0x00FF);
	// out.write(value & 0x00FF);
	// return 4;
	// } catch (IOException e) {
	// throw new RuntimeIOException(e.getMessage(), e);
	// }
	// }

	public static void toBytes(short value, byte[] bytes, int offset) {
		bytes[offset] = (byte) ((value >>> 8) & 0x00FF);
		bytes[offset + 1] = (byte) (value & 0x00FF);
	}

	public static void toBytes_BigEndian(short value, byte[] bytes, int offset) {
		bytes[offset] = (byte) ((value >>> 8) & 0x00FF);
		bytes[offset + 1] = (byte) (value & 0x00FF);
	}

	public static void toBytes(char value, byte[] bytes, int offset) {
		bytes[offset] = (byte) ((value >>> 8) & 0x00FF);
		bytes[offset + 1] = (byte) (value & 0x00FF);
	}

	/**
	 * 将 long 值转为8字节的二进制数组；
	 * 
	 * @param value  要转换的long整数；
	 * @param bytes  要保存转换结果的二进制数组；转换结果将从高位至低位的顺序写入数组从 offset 指定位置开始的8个元素；
	 * @param offset 写入转换结果的起始位置；
	 * @return 返回写入的长度；
	 */
	public static int toBytes(long value, byte[] bytes, int offset) {
		bytes[offset] = (byte) ((value >>> 56) & 0x00FF);
		bytes[offset + 1] = (byte) ((value >>> 48) & 0x00FF);
		bytes[offset + 2] = (byte) ((value >>> 40) & 0x00FF);
		bytes[offset + 3] = (byte) ((value >>> 32) & 0x00FF);
		bytes[offset + 4] = (byte) ((value >>> 24) & 0x00FF);
		bytes[offset + 5] = (byte) ((value >>> 16) & 0x00FF);
		bytes[offset + 6] = (byte) ((value >>> 8) & 0x00FF);
		bytes[offset + 7] = (byte) (value & 0x00FF);
		return 8;
	}

	// public static int toBytes(long value, OutputStream out) {
	// try {
	// out.write((int) ((value >>> 56) & 0x00FF));
	// out.write((int) ((value >>> 48) & 0x00FF));
	// out.write((int) ((value >>> 40) & 0x00FF));
	// out.write((int) ((value >>> 32) & 0x00FF));
	// out.write((int) ((value >>> 24) & 0x00FF));
	// out.write((int) ((value >>> 16) & 0x00FF));
	// out.write((int) ((value >>> 8) & 0x00FF));
	// out.write((int) (value & 0x00FF));
	// return 8;
	// } catch (IOException e) {
	// throw new RuntimeIOException(e.getMessage(), e);
	// }
	// }

	public static byte[] toBytes(String str) {
		return toBytes(str, DEFAULT_CHARSET);
	}

	public static byte[] toBytes(String str, String charset) {
		if (null == str) {
			return null;
		}
		try {
			byte[] bytes = str.getBytes(charset);
			return bytes;
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeIOException(e.getMessage(), e);
		}
	}

	/**
	 * 以默认字符集({@value #DEFAULT_CHARSET})生成字符串；
	 * 
	 * @param bytes
	 * @return
	 */
	public static String toString(byte[] bytes) {
		return toString(bytes, DEFAULT_CHARSET);
	}

	/**
	 * 以默认字符集({@value #DEFAULT_CHARSET})生成字符串；
	 * 
	 * @param bytes
	 * @param offset
	 * @return
	 */
	public static String toString(byte[] bytes, int offset) {
		return toString(bytes, offset, bytes.length - offset, DEFAULT_CHARSET);
	}

	/**
	 * 以默认字符集({@value #DEFAULT_CHARSET})生成字符串；
	 * 
	 * @param bytes
	 * @param offset
	 * @param len
	 * @return
	 */
	public static String toString(byte[] bytes, int offset, int len) {
		return toString(bytes, offset, len, DEFAULT_CHARSET);
	}

	/**
	 * 以指定字符集生成字符串；
	 * 
	 * @param bytes
	 * @param charset
	 * @return
	 */
	public static String toString(byte[] bytes, String charset) {
		return toString(bytes, 0, bytes.length, charset);
	}

	/**
	 * 以指定字符集生成字符串；
	 * 
	 * @param bytes
	 * @param offset
	 * @param len
	 * @param charset
	 * @return
	 */
	public static String toString(byte[] bytes, int offset, int len, String charset) {
		try {
			if (bytes == null) {
				return null;
			}
			if (len == 0) {
				return "";
			}
			return new String(bytes, offset, len, charset);
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeIOException(e.getMessage(), e);
		}
	}

	public static boolean toBoolean(byte value) {
		return value != FALSE_BYTE;
	}

	/**
	 * 按从高位到低位的顺序将指定二进制数组从位置 0 开始的 4 个字节转换为 int 整数；
	 * 
	 * @param bytes 要转换的二进制数组；
	 * @return 转换后的 int 整数；
	 */
	public static int toInt(byte[] bytes) {
		int length = bytes.length;
		if(length < 4) {
			byte[] buffer = new byte[4];
			System.arraycopy(bytes, 0, buffer, buffer.length - length, length);
			return toInt(buffer, 0);
		} else {
			return toInt(bytes, 0);
		}
		// value = (value | (bytes[0] & 0xFF)) << 8;
		// value = (value | (bytes[1] & 0xFF)) << 8;
		// value = (value | (bytes[2] & 0xFF)) << 8;
		// value = value | (bytes[3] & 0xFF);
		//
		// return value;
	}

	/**
	 * 按从高位到低位的顺序将指定二进制数组从 offset 参数指定的位置开始的 2 个字节转换为 short 整数；
	 * 
	 * @param bytes  要转换的二进制数组；
	 * @param offset 要读取数据的开始位置
	 * @return 转换后的 short 整数；
	 */
	public static short toShort(byte[] bytes, int offset) {
		short value = 0;
		value = (short) ((value | (bytes[offset] & 0xFF)) << 8);
		value = (short) (value | (bytes[offset + 1] & 0xFF));

		return value;
	}

	public static short toShort(byte[] bytes) {
		return toShort(bytes, 0);
	}

	public static char toChar(byte[] bytes, int offset) {
		char value = 0;
		value = (char) ((value | (bytes[offset] & 0xFF)) << 8);
		value = (char) (value | (bytes[offset + 1] & 0xFF));

		return value;
	}

	/**
	 * 按从高位到低位的顺序将指定二进制数组从 offset 参数指定的位置开始的 4 个字节转换为 int 整数；
	 * 
	 * @param bytes  要转换的二进制数组；
	 * @param offset 要读取数据的开始位置
	 * @return 转换后的 int 整数；
	 */
	public static int toInt(byte[] bytes, int offset) {
		// int value = 0;
		// value = (value | (bytes[offset] & 0xFF)) << 8;
		// value = (value | (bytes[offset + 1] & 0xFF)) << 8;
		// value = (value | (bytes[offset + 2] & 0xFF)) << 8;
		// value = value | (bytes[offset + 3] & 0xFF);
		//
		// return value;
		return toInt(bytes, offset, 4);
	}

	/**
	 * 按从高位到低位的顺序将指定二进制数组从 offset 参数指定的位置开始的 4 个字节转换为 int 整数；
	 * 
	 * @param bytes  要转换的二进制数组；
	 * @param offset 要读取数据的开始位置
	 * @return 转换后的 int 整数；
	 * 
	 * @param len 长度；len 必须满足： len 大于等于 1 且小于等于4；
	 * @return 转换后的 int 整数；
	 */
	public static int toInt(byte[] bytes, int offset, int len) {
		// if (len < 1 || len > 4) {
		// throw new IllegalArgumentException("Len less than 1 or greate than 4!");
		// }
		// int value = 0;
		// for (int i = 0; i < len; i++) {
		// value = value | ((bytes[offset + i] & 0xFF) << (8 * (3 - i)));
		// }
		//
		// return value;
		return toInt(bytes, offset, len, true);
	}

	/**
	 * 按从高位到低位的顺序将指定二进制数组从 offset 参数指定的位置开始的 4 个字节转换为 int 整数；
	 * 
	 * @param bytes  要转换的二进制数组；
	 * @param offset 要读取数据的开始位置
	 * @return 转换后的 int 整数；
	 * 
	 * @param len       长度；len 必须满足： len 大于等于 1 且小于等于4；
	 * @param highAlign 是否高位对齐；<br>
	 *                  true 表示参数 bytes 的首个字节对应为整数的最高8位；<br>
	 *                  false 表示参数 bytes 的最后字节对应为整数的最低8位；
	 * @return 转换后的 int 整数；
	 */
	public static int toInt(byte[] bytes, int offset, int len, boolean highAlign) {
		if (len < 1 || len > 4) {
			throw new IllegalArgumentException("Len less than 1 or greate than 4!");
		}
		int value = 0;
		if (highAlign) {
			for (int i = 0; i < len; i++) {
				value = value | ((bytes[offset + i] & 0xFF) << (8 * (3 - i)));
			}
		} else {
			for (int i = 0; i < len; i++) {
				value = value | ((bytes[offset + i] & 0xFF) << (8 * (len - 1 - i)));
			}
		}

		return value;
	}

	public static long toLong(byte[] bytes) {
		return toLong(bytes, 0);
	}

	/**
	 * 按从高位到低位的顺序将指定二进制数组从 offset 参数指定的位置开始的 8个字节转换为 long 整数；
	 * 
	 * @param bytes  要转换的二进制数组；
	 * @param offset 要读取数据的开始位置
	 * @return 转换后的 long 整数；
	 */
	public static long toLong(byte[] bytes, int offset) {
		long value = 0;
		value = (value | (bytes[offset] & 0xFF)) << 8;
		value = (value | (bytes[offset + 1] & 0xFF)) << 8;
		value = (value | (bytes[offset + 2] & 0xFF)) << 8;
		value = (value | (bytes[offset + 3] & 0xFF)) << 8;
		value = (value | (bytes[offset + 4] & 0xFF)) << 8;
		value = (value | (bytes[offset + 5] & 0xFF)) << 8;
		value = (value | (bytes[offset + 6] & 0xFF)) << 8;
		value = value | (bytes[offset + 7] & 0xFF);

		return value;
	}

	/**
	 * 从指定的输入流中读入2个字节，由前到后按由高位到低位的方式转为 short 整数；
	 * 
	 * @param in in
	 * @return short
	 */
	public static short readShort(InputStream in) {
		try {
			int v = in.read();
			if (v < 0) {
				throw new IllegalDataException("No enough data to read as short from the specified input stream!");
			}
			int value = (v & 0xFF) << 8;

			v = in.read();
			if (v < 0) {
				throw new IllegalDataException("No enough data to read as short from the specified input stream!");
			}
			value = value | (v & 0xFF);
			return (short) value;
		} catch (IOException e) {
			throw new RuntimeIOException(e.getMessage(), e);
		}
	}

	public static int writeShort(short value, OutputStream out) {
		try {
			out.write((value >>> 8) & 0x00FF);
			out.write(value & 0x00FF);
			return 2;
		} catch (IOException e) {
			throw new RuntimeIOException(e.getMessage(), e);
		}
	}

	/**
	 * 从指定的输入流中读入4个字节，由前到后按由高位到低位的方式转为 int 整数；
	 * 
	 * @param in in
	 * @return int
	 */
	public static int readInt(InputStream in) {
		try {
			int value = 0;
			int v0 = in.read();
			int v1 = in.read();
			int v2 = in.read();
			int v3 = in.read();
			if (v0 < 0 || v1 < 0 || v2 < 0 || v3 < 0) {
				throw new IllegalDataException("No enough data to read as integer from the specified input stream!");
			}
			value = (v0 << 24) | (v1 << 16) | (v2 << 8) | v3;
			return value;
		} catch (IOException e) {
			throw new RuntimeIOException(e.getMessage(), e);
		}
	}

	public static int writeInt(int value, OutputStream out) {
		try {
			out.write((value >>> 24) & 0x00FF);
			out.write((value >>> 16) & 0x00FF);
			out.write((value >>> 8) & 0x00FF);
			out.write(value & 0x00FF);
			return 4;
		} catch (IOException e) {
			throw new RuntimeIOException(e.getMessage(), e);
		}
	}

	public static long readLong(InputStream in) {
		try {
			long value = 0;
			int v;
			for (int i = 0; i < 7; i++) {
				v = in.read();
				if (v < 0) {
					throw new IllegalDataException(
							"No enough data to read as long integer from the specified input stream!");
				}
				value = (value | (v & 0xFF)) << 8;
			}
			value = value | (in.read() & 0xFF);

			return value;
		} catch (IOException e) {
			throw new RuntimeIOException(e.getMessage(), e);
		}
	}

	public static int writeLong(long value, OutputStream out) {
		try {
			out.write((int) ((value >>> 56) & 0x00FF));
			out.write((int) ((value >>> 48) & 0x00FF));
			out.write((int) ((value >>> 40) & 0x00FF));
			out.write((int) ((value >>> 32) & 0x00FF));
			out.write((int) ((value >>> 24) & 0x00FF));
			out.write((int) ((value >>> 16) & 0x00FF));
			out.write((int) ((value >>> 8) & 0x00FF));
			out.write((int) (value & 0x00FF));
			return 8;
		} catch (IOException e) {
			throw new RuntimeIOException(e.getMessage(), e);
		}
	}

	public static byte readByte(InputStream in) {
		try {
			int value = in.read();
			if (value < 0) {
				throw new IllegalDataException("No byte to read from the input stream!");
			}
			return (byte) value;
		} catch (IOException e) {
			throw new RuntimeIOException(e.getMessage(), e);
		}
	}

	public static byte[] readBytes(InputStream in) {
		ByteArrayOutputStream outStream = new ByteArrayOutputStream();
		try {
			byte[] buffer = new byte[BUFFER_SIZE];
			int len = -1;
			while ((len = in.read(buffer)) != -1) {
				outStream.write(buffer, 0, len);
			}
			outStream.close();
			return outStream.toByteArray();
		} catch (IOException e) {
			throw new RuntimeIOException(e.getMessage(), e);
		}
	}

	public static void writeByte(byte value, OutputStream out) {
		try {
			out.write(value);
		} catch (IOException e) {
			throw new RuntimeIOException(e.getMessage(), e);
		}
	}

	public static byte[] concat(byte[]... bytesList) {
		int size = 0;
		for (byte[] bs : bytesList) {
			size += bs.length;
		}
		byte[] bytesAll = new byte[size];
		size = 0;
		for (byte[] bs : bytesList) {
			System.arraycopy(bs, 0, bytesAll, size, bs.length);
			size += bs.length;
		}

		return bytesAll;
	}

	public static byte[] concat(Bytes... bytesList) {
		int size = 0;
		for (Bytes bs : bytesList) {
			size += bs.size();
		}

		byte[] bytesAll = new byte[size];
		size = 0;
		for (Bytes bs : bytesList) {
			bs.copyTo(bytesAll, size, bs.size());
			size += bs.size();
		}

		return bytesAll;
	}

	public static byte[] concat(ByteSequence... bytesList) {
		int size = 0;
		for (ByteSequence bs : bytesList) {
			size += bs.size();
		}

		byte[] bytesAll = new byte[size];
		size = 0;
		for (ByteSequence bs : bytesList) {
			size += bs.copyTo(bytesAll, size, bs.size());
		}

		return bytesAll;
	}

	public static char[] concat(char[]... bytesList) {
		int size = 0;
		for (char[] bs : bytesList) {
			size += bs.length;
		}
		char[] bytesAll = new char[size];
		size = 0;
		for (char[] bs : bytesList) {
			System.arraycopy(bs, 0, bytesAll, size, bs.length);
			size += bs.length;
		}

		return bytesAll;
	}

	public static long toLong(ByteArray byteArray) {
		return toLong(byteArray.bytes());
	}

	/**
	 * 从字节数组获取对象
	 * 
	 * @param objBytes objBytes
	 * @return object
	 * @throws Exception exception
	 */
	// public static Object getObjectFromBytes(byte[] objBytes) throws Exception {
	// if (objBytes == null || objBytes.length == 0) {
	// return null;
	// }
	// ByteArrayInputStream bi = new ByteArrayInputStream(objBytes);
	// ObjectInputStream oi = new ObjectInputStream(bi);
	// return oi.readObject();
	// }

	/**
	 * 从对象获取一个字节数组;
	 * 
	 * @param obj obj
	 * @return byte array
	 * @throws Exception exception
	 */
	public static byte[] getBytesFromObject(Object obj) throws Exception {
		if (obj == null) {
			return null;
		}
		ByteArrayOutputStream bo = new ByteArrayOutputStream();
		ObjectOutputStream oo = new ObjectOutputStream(bo);
		oo.writeObject(obj);
		return bo.toByteArray();
	}

	public static boolean startsWith(byte[] srcBytes, byte[] prefixBytes) {
		for (int i = 0; i < prefixBytes.length; i++) {
			if (prefixBytes[i] != srcBytes[i]) {
				return false;
			}
		}
		return true;
	}

}
