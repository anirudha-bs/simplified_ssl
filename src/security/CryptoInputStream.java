package security;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;

public class CryptoInputStream extends FilterInputStream
{
  protected Hash H;
  protected byte[] K;
  protected byte[] buffer;
  protected int pointer;

  public CryptoInputStream(InputStream paramInputStream, byte[] paramArrayOfByte, Hash paramHash)
  {
    super(paramInputStream);
    this.H = paramHash;
    this.K = paramArrayOfByte;
    this.pointer = 0;
  }

  public int available()
    throws IOException
  {
    int i = super.available();
    return i / this.H.getPacketSize() * this.H.getNumberOfDataBytes();
  }

  public int read()
    throws IOException
  {
    if (this.pointer == 0) {
     int i = 0;
      byte[] arrayOfByte = new byte[this.H.getPacketSize()];
      for (int k = 0; k < this.H.getPacketSize(); k++)
      {
        int m = this.in.read();
        if (m == -1) {
          if (k == 0) return -1;

          throw new IOException("Data Reading ERROR !!!");
        }
        arrayOfByte[(i++)] = ((byte)m);
      }

      try
      {
        arrayOfByte = OneTimeKey.xor(arrayOfByte, this.K);
        this.buffer = this.H.unpack(arrayOfByte);
      }
      catch (RuntimeException localRuntimeException) {
        System.out.println(localRuntimeException);
      }
      catch (Exception localException) {
        throw new IOException("Reading ERROR !!!");
      }
    }

    int i = this.buffer[this.pointer];
    int j = this.buffer.length;
    this.pointer = ((this.pointer + 1) % j);
    return i;
  }

  public int read(byte[] paramArrayOfByte, int paramInt1, int paramInt2)
    throws IOException
  {
    if (paramArrayOfByte == null) throw new NullPointerException("Empty Buffer");

    int k = this.H.getPacketSize();
    int m = this.H.getNumberOfDataBytes();

    int i = paramInt1 / m;
    int j = paramInt1 % m;

    int n = (paramInt2 + j) / k;
    int i2 = (paramInt2 + j) % k;

    if (i2 != 0) {
      n++;
    }
    byte[] arrayOfByte2 = new byte[n * k];
    int i3 = i * k;
    int i4 = n * k;
    try
    {
      if (super.available() >= i4) {
        int i1 = this.in.read(arrayOfByte2, i3, i4);
        if (i1 == -1) return i1;
        byte[] arrayOfByte1 = OneTimeKey.xor(arrayOfByte2, this.K);
        arrayOfByte1 = this.H.unpack(arrayOfByte1);
        System.arraycopy(arrayOfByte1, 0, paramArrayOfByte, 0, arrayOfByte1.length);
        return i1 / k * m;
      }
      return 0;
    }
    catch (Exception localException) {
      System.out.println("Decryption ERROR !!!");
    }
    return 0;
  }

  public long skip(long paramLong) throws IOException
  {
    for (long l = 0L; l < paramLong; l += 1L)
      if (read() == -1) return l;
    return paramLong;
  }
}