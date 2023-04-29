/**
 * 
 */
package javacardapp;

import javacard.framework.APDU;
import javacard.framework.APDUException;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.DESKey;
import javacard.security.KeyBuilder;
import javacardx.crypto.Cipher;

/**
 * @author Petr Dzurenda
 *
 */
public class MainApp extends Applet {

    private static final byte CLA_APPLICATION          = (byte) 0x80;
    private static final byte INS_SEND_DATA            = (byte) 0x01;
    private static final byte INS_SEND_SW_NO_ERROR     = (byte) 0x00;
    
    private final byte[] data;
    private short offset;
    
    private final byte key[] = {(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08};
    private final byte openText[] = {(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08};
		
	/**
	 * In the constructor we create an instance of the applet.
	 * If this operation could be performed, the registered method
	 * of the base class is called to register this
	 * applet instance with the JCRE.
	 * @param array the array containing installation parameters.
	 * @param offset the starting offset in buffer.
	 * @param length the length in bytes of the parameter data in buffer.
	 * The maximum value of length is 32.
	 */
	public MainApp(byte[] array, short offset, byte length) {
		// Length of the buffer array is coded in the first byte of the buffer.
		register(array, (short) (offset + 1), array[offset]);
                
                data = new byte[128];
                offset = 0;
	}

	/**
	 * Static method invoked by the JCRE (JavaCard Runtime Environment)
	 * to instantiate an applet instance and register it with the JCRE.<br>
	 * We only instantiate the applet in this method.
	 * @param buffer the array containing installation parameters.
	 * @param offset the starting offset in buffer.
	 * @param length the length in bytes of the parameter data in buffer.
	 * The maximum value of length is 32.
	 */
	public static void install(byte[] buffer, short offset, byte length) {
		new MainApp(buffer, offset, length);
                
                
	}

	/* (non-Javadoc)
	 * @see javacard.framework.Applet#process(javacard.framework.APDU)
	 */
	public void process(APDU apdu) throws ISOException {
	// TODO Auto-generated method stub
		
	byte buffer[] = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();
       
        byte cla = buffer[ISO7816.OFFSET_CLA];
        byte ins = buffer[ISO7816.OFFSET_INS];

        if (selectingApplet()) {
            return;
        }

        if (cla != CLA_APPLICATION) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
        
        switch (ins) {
            case INS_SEND_DATA: {
             offset = 0; 
             Util.arrayFillNonAtomic(data, offset, (short) data.length, (byte) 0);
             
            // CREATE DES KEY OBJECT
            DESKey m_desKey = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES,false);

            // SET KEY VALUE
            m_desKey.setKey(key, (short) 0);
            
            // CREATE OBJECTS FOR ECB CIPHERING
            Cipher m_encryptCipher = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD, false);

            // INIT CIPHER WITH KEY FOR ENCRYPT DIRECTION
            m_encryptCipher.init(m_desKey, Cipher.MODE_ENCRYPT);

            m_encryptCipher.doFinal(buffer, ISO7816.OFFSET_CDATA, dataLen, data, (short) 0);


            send(apdu);

            break;
            }
            case INS_SEND_SW_NO_ERROR: {
               
                ISOException.throwIt(ISO7816.SW_NO_ERROR);
                

                break;
            }
           
          
            default: {
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);

                break;
            }
        }
        
                
	}
        
        /**
     * Sends the data, this method works in both T0 and T1.
     *
     * @param apdu the incoming APDU object
     * @throws APDUException with the reason code
     */
    private void send(APDU apdu) throws APDUException {
        short sendLength;

        short blockSize = APDU.getOutBlockSize();

        // set outgoing
        short bytesLeft = apdu.setOutgoing();
        apdu.setOutgoingLength(bytesLeft);

        // send data
        while (bytesLeft > 0) {
            sendLength = (blockSize < bytesLeft ? blockSize : bytesLeft);
            apdu.sendBytesLong(data, offset, sendLength);
            offset += sendLength;

            bytesLeft -= sendLength;
        }
    }

   
	
	

}
