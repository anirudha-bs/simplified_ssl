package security;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;

public class CryptoOutputStream extends FilterOutputStream
{
  protected Hash H;
  protected byte[] K;
  private byte[] buffer;
  private int pointer;

  public CryptoOutputStream(OutputStream paramOutputStream, byte[] paramArrayOfByte, Hash paramHash)
  {
    super(paramOutputStream);
    this.H = paramHash;
    this.K = paramArrayOfByte;
    int i = paramHash.getNumberOfDataBytes();
    this.buffer = new byte[i];
    this.pointer = 0;
  }

  public void flush()
    throws IOException
  {
    if (this.pointer != 0)
      shallowFlush();
    super.flush();
  }

  protected void shallowFlush()
    throws IOException
  {
    if (this.pointer != 0)
    {
      write(this.buffer, 0, this.pointer);
      this.pointer = 0;
    }
  }

  public void write(int paramInt)
    throws IOException
  {
    this.buffer[(this.pointer++)] = ((byte)paramInt);
    if (this.pointer == this.buffer.length) {
      this.pointer = 0;
      write(this.buffer, 0, this.buffer.length);
    }
  }

  public void write(byte[] paramArrayOfByte, int paramInt1, int paramInt2)
    throws IOException
  {
    byte[] arrayOfByte1 = new byte[paramInt2];
    System.arraycopy(paramArrayOfByte, paramInt1, arrayOfByte1, 0, paramInt2);
    try {
      byte[] arrayOfByte2 = this.H.pack(arrayOfByte1);
      arrayOfByte2 = OneTimeKey.xor(arrayOfByte2, this.K);
      this.out.write(arrayOfByte2);
    }
    catch (Exception localException) {
      System.out.println(localException);
    }
  }
}