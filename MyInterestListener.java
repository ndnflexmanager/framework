package org.ccnx.ccn.utils;

import java.lang.*;
import java.io.*;
import java.util.*;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.Key;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.logging.Level;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

import org.ccnx.ccn.CCNHandle;
import org.ccnx.ccn.CCNInterestListener;
import org.ccnx.ccn.config.SystemConfiguration;
import org.ccnx.ccn.impl.security.crypto.ContentKeys;
import org.ccnx.ccn.impl.support.DataUtils;
import org.ccnx.ccn.impl.support.Log;
import org.ccnx.ccn.io.content.Link.LinkObject;
import org.ccnx.ccn.profiles.SegmentationProfile;
import org.ccnx.ccn.profiles.VersioningProfile;
import org.ccnx.ccn.profiles.security.access.AccessControlManager;
import org.ccnx.ccn.profiles.security.access.AccessDeniedException;
import org.ccnx.ccn.protocol.ContentName;
import org.ccnx.ccn.protocol.ContentObject;
import org.ccnx.ccn.protocol.Exclude;
import org.ccnx.ccn.protocol.ExcludeComponent;
import org.ccnx.ccn.protocol.Interest;
import org.ccnx.ccn.protocol.KeyLocator;
import org.ccnx.ccn.protocol.PublisherPublicKeyDigest;
import org.ccnx.ccn.protocol.SignedInfo.ContentType;
import org.ccnx.ccn.io.CCNReader;

/**
 *This class is used for catch interest in push petitions after the first exchange of messages.
 */

public class MyInterestListener implements CCNInterestListener  {


        private ContentName argName;
        private String maID;
        private MEInterface applicationMe;
	private MAInterface applicationMa;
	private SecretKey key;
	private byte [] iv;
	private int type;

       /**
	*public MyInterestListener(ContentName argName, String maID, ApplicationME application)
	*
	*Constructor for ME
	*
	*@param argName		data's name
	*@param maID		MA's id 
	*@param application	application which uses this api
	*
	*/

        public MyInterestListener(ContentName argName, String maID, MEInterface application,SecretKey key,byte [] iv){

                this.argName=argName;
                this.maID=maID;
                applicationMe=application;
		this.key=key;
                this.iv = iv;
		type=3;

        }

       /**
	*public MyInterestListener(ContentName argName, ApplicationMA application)
	*
	*Constructor for MA
	*
	*@param argName		data's name
	*@param application	application which uses this api
	*
	*/

	public MyInterestListener(ContentName argName, MAInterface application,SecretKey key,byte [] iv){

                this.argName=argName;
                applicationMa=application;
		this.key=key;
                this.iv = iv;
		type=2;

        }

       /**
        *public MyInterestListener(ContentName argName, ApplicationMA application)
        *
        *Constructor for check the exchange of the SecretKey
        *
        *@param key		SecretKey         
        *@param iv     		algorithm parameters
        *
        */
	
	public MyInterestListener(SecretKey key,byte [] iv){
		
		this.key=key;
		this.iv = iv;
		type=1;
	}

       /**
        *private static byte[] decrypt(byte[] inpBytes, Key key,byte[] iv)
        *       
        *This function decrypt input data for SecretKey encryptions
        *
        *
        *@param inpBytes        bytes for decrypt
        *@param key             key which use for decrypt
        *@param iv              
        *
        *@return byte[]         decrypt data
        *
        */

	private static byte[] decrypt(byte[] inpBytes,Key  key, byte [] iv) throws Exception{

		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");		
                cipher.init(Cipher.DECRYPT_MODE, key,new IvParameterSpec(iv));
		return cipher.doFinal(inpBytes);
        }


       /**
	* public Interest handleContent(ContentObject result, Interest interest)
	*
	*This function catch the interest and 
	*
	*@param result		interest's data
	*@param interest	interest to be catch
	*
	*@return Interest	(without effect)
	*
	*/

         public Interest handleContent(ContentObject result, Interest interest) {
                try{	
                        byte []data=result.content();
			data = this.decrypt(data,key,iv);

			if(type==1){

				if(data[0]==11){
	                                System.out.println("the key has been transfered correctly("+data[0]+")");
				}

			}else if(type==2){

				applicationMa.handleContent(argName, data);				
			}else{	
	      			applicationMe.handleContent(argName, data,maID);
			}
                }catch(Exception e){
			System.out.println("Something wrong happens in MyIL!!!");
                        System.out.println(e);

                }

                 return(null);
        }

}

