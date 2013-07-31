

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
import javax.crypto.SecretKeyFactory; 
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKey;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

import org.ccnx.ccn.impl.security.keys.BasicKeyManager;
import org.apache.commons.codec.binary.Base64;
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
import org.ccnx.ccn.protocol.CCNTime;
import org.ccnx.ccn.protocol.ContentName;
import org.ccnx.ccn.protocol.ContentObject;
import org.ccnx.ccn.protocol.Exclude;
import org.ccnx.ccn.protocol.ExcludeComponent;
import org.ccnx.ccn.protocol.Interest;
import org.ccnx.ccn.protocol.KeyLocator;
import org.ccnx.ccn.protocol.PublisherPublicKeyDigest;
import org.ccnx.ccn.protocol.SignedInfo.ContentType;
import org.ccnx.ccn.io.CCNReader;
import org.ccnx.ccn.CCNFilterListener;

public class ManagementEntity implements CCNFilterListener{


	private String networkPrefix; 
	private CCNHandle handle;
	private String meID;
	private String managementCase;
	private String prefix;

	private MEInterface application;
	
	private Hashtable repoData;
	private Hashtable MAData;


	private PublicKey pKey;
	private PrivateKey pvKey;


	private static String algorithm="AES/CBC/PKCS5Padding";

	private byte [] iv = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x10,0x11,0x12,0x13,0x14,0x15};

	private ccnBase64 bas;

	private static final byte ACCEPT=1;
        private static final byte REJECT=0;
	private static final long TIME=1000;
	private static final String INTER="/Interest";
	private static final String BOOTSTRAP="/ME";
	private static final String KEY="/setKey";
	private static final String NONCE="/nonce";

       /**
	*public ManagementEntity (String networkPrefix, String managementCase, String meID, ApplicationME application)
	*
	*Constructor.  All String parameters must start with slash ("/")
	*
	*@param networkPrefix		net's prefix
	*@param managementCase		net's prefix
	*@param meID			ManagementEntity identificator
	*@param application		application which uses this api
	*
	*/

	public ManagementEntity (String networkPrefix, String managementCase, String meID, MEInterface application)throws Exception{


		this.networkPrefix = new String(networkPrefix);
		this.managementCase= new String(managementCase);
		this.meID= new String(meID);
		prefix = new String(networkPrefix+managementCase);
		repoData = new Hashtable();
		MAData = new Hashtable();
		bas=new ccnBase64();
		this.application=application;
		handle = CCNHandle.open();
		ContentName filter = ContentName.fromURI(prefix);                
		handle.registerFilter(filter, this);

	}

       /**
	*private static byte[] encrypt(byte[] inpBytes, Key key, String xform,byte[] iv)
	*	
	*This function encrypt input data for SecretKey
	*
	*
	*@param	inpBytes	bytes for encrytp
	*@param key		key which use for encrypt
	*@param xform		algorithm for encrypt
	*@param iv		
	*
	*@return byte[]		encrypt data
	*
	*/

        private static byte[] encrypt(byte[] inpBytes, Key key, String xform,byte[] iv) throws Exception {
                 Cipher cipher = Cipher.getInstance(xform);
                 cipher.init(Cipher.ENCRYPT_MODE, key,new IvParameterSpec(iv));
                 return cipher.doFinal(inpBytes);
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

        private static byte[] decrypt(byte[] inpBytes, Key key,byte[] iv) throws Exception{
		Cipher cipher = Cipher.getInstance(algorithm);
                cipher.init(Cipher.DECRYPT_MODE,key,new IvParameterSpec(iv));
                return cipher.doFinal(inpBytes);
        }

       /**
        *private static byte[] decryptP(byte[] inpBytes, Key key, String xform)
	*       
        *This function decrypt input data for PrublicKey encryptions
        *
        *
        *@param inpBytes        bytes for decrytp
        *@param key             key which use for decrypt
        *@param xform           algorithm for decrypt
        *
        *@return byte[]         decrypt data
        *
        */

	private static byte[] decryptP(byte[] inpBytes, Key key, String xform) throws Exception{

		Cipher cipherP = Cipher.getInstance(xform);
                cipherP.init(Cipher.DECRYPT_MODE,key);
                return cipherP.doFinal(inpBytes);
        }

       /**
        *private void sendMeid()
        *
        *This method initializes public and private key, then sends meID info and public key to MA
        *
        */

	private void sendMeid()throws Exception{
		
		ContentName argName=ContentName.fromURI(prefix+BOOTSTRAP+meID);
		/*Initialize keys*/
		if(pKey==null){		
			BasicKeyManager bkm= new BasicKeyManager();
                	bkm.initialize();
		
			pKey=bkm.getPublicKey(handle.getDefaultPublisher());
			String stringKey = bas.encodeToString(pKey.getEncoded());
			pvKey=bkm.getSigningKey (handle.getDefaultPublisher());
		}
//		String stringKey = bas.encodeToString(pKey.getEncoded());
		
		/*Send message with meID info and public key*/
		ContentObject co = ContentObject.buildContentObject (argName,ContentType.DATA,pKey.getEncoded(), null, null, null, 0, null);
                if ( handle.put(co) == null) System.out.println("Error: ContentObject could not be put in the CS");
	}




       /**
        *private void testKey(ContentName contentN, Interest interest)
        *
        *This method creates the secret key and sends a challenge to MA for check if it creates the key correctly
	*
	*@param contentN	for search the correct secret key
	*@param	interest	for send ack message
        *
        */

	private void testKey(ContentName contentN, Interest interest, String maID)throws Exception{

		/*Send key has been received*/
		byte [] data = new byte[] {1};
                ContentObject co = ContentObject.buildContentObject(interest.name(),ContentType.DATA, data, null, null, null,0, null);
                if ( handle.put(co) == null) System.out.println("Error: ContentObject could not be put in the CS");

		/*Decode key*/
	//	String stringKey = this.base64Filter((contentN.toString()).toCharArray())/**/;
		byte[] encodedKey=bas.decode(contentN.toString());//stringKey);
		encodedKey=this.decryptP(encodedKey,pvKey, "RSA");
		//stringKey = new String(encodedKey,"UTF-8");
		//encodedKey=bas.decode(stringKey);
    		SecretKey key = new SecretKeySpec(encodedKey, 0, encodedKey.length, "AES"); 
		MAData.put(maID,key);

		/*Send a challenge for check that both use the same key*/
		String stringChallenge ="";
		byte [] test= new byte[]{10};//We expect 11 as response
		try{		
		byte [] encryptChallenge=this.encrypt(test, key, algorithm,iv);
		stringChallenge = bas.encodeToString(encryptChallenge);

		}catch(Exception e){

			System.out.println("encode Error");
			System.out.println(e);
		}	

		ContentName argName=ContentName.fromURI(prefix+maID+meID+NONCE+"/"+stringChallenge);

		interest = new Interest(argName);
		MyInterestListener myIL = new MyInterestListener(key,iv);
		handle.expressInterest(interest, myIL);
		
	}

       /**
        *private ContentName filterName(String name_cont)
        *
        *This method filters interest name and decodes it if is necessary
        *
        *@param name_cont       interest name
        *
	*@return ContentName  	filtered and decoded interest name
        *
        */

	private ContentName filterName(String name_cont, String maID)throws Exception{
		
		int length_prefix =0;
		SecretKey key=(SecretKey)MAData.get(maID);

		if(name_cont.contains(KEY.toString())){
      			length_prefix = prefix.length()+meID.length()+maID.length()+KEY.length();

                }else{

	                length_prefix = prefix.length()+meID.length()+maID.length();
                }       

		/*Look for interest for the application*/                                
                String decrypted_name = name_cont.substring(length_prefix);
                
		/*If name is encrypted*/                
                if(!(name_cont.contains(KEY.toString()))){
                                
                	try{
                		//decrypted_name=this.base64Filter(decrypted_name.toCharArray());
                        	byte[] crpt  = bas.decode(decrypted_name);
                        	crpt=this.decrypt(crpt,key,iv);
                        	decrypted_name=new String(crpt, "UTF-8");

                	}catch(Exception e){

			}

                }
		return ContentName.fromURI(decrypted_name);

	}

       /**
	*private void searchMaID(char [] name)
	*
	*This function extracts the maID
	*
	*@param name		interest name which contents the MA name	
	*/
	private String searchMaID(char [] name){

		int i=prefix.length()+meID.length()+1;
                                String ma= "/";
                                while(name[i] !='/'){

                                        ma=ma+name[i];
                                        i++;
                                }

                 return ma;
		
	}

       /**
        *private boolean pushAuthorization(Interest interest,ContentName contentN)
        *
        *This function asks to the application for an authirization
        *
        *@param interest            interest which needs authorization
	*@param contentN	    name of the data required
	*
	*@return boolean	    true if the authorization is confirmed        
        */

	private boolean pushAuthorization(Interest interest,ContentName contentN, String maID)throws Exception{

		ContentObject co_int;
            	byte [] acceptation = new byte[1];

                /*Ask for communication accepted*/
                if(application.authorizeContent(contentN,maID)==true){
    	            acceptation[0]=ACCEPT;
                }else{
                    acceptation[0]=REJECT;
                }

		SecretKey key=(SecretKey)MAData.get(maID);
                byte [] accept=this.encrypt(acceptation, key, algorithm,iv);

                co_int= ContentObject.buildContentObject (interest.name(),ContentType.DATA, accept, null, null, null, 0, null);
                /*Return accept or not message*/
               	if ( handle.put(co_int) == null) System.out.println("Error: ContentObject could not be put in the CS");
		
		if (acceptation[0]==ACCEPT){

			return true;
		}else{

			return false;
		}
	}

       /**
	*public byte[] pull(ContentName argName, String maID)
	*
	*This method asks for a data through an interest and returns it
	*
	*@param argName name of interest data
	*@param maID	ManagementAgent identificator
	*@return byte[] response's content
	*
	*/

	public byte[] pull(ContentName argName, String maID)throws IOException{

		try {	
			SecretKey key=(SecretKey)MAData.get(maID);
			
			byte [] crpt=this.encrypt(argName.toString().getBytes(), key, algorithm,iv);
                        String encrpt_argName= bas.encodeToString(crpt);
                        argName=ContentName.fromURI(prefix+maID+meID+"/"+encrpt_argName);/*Interest's name*/
                        Interest interest = new Interest(argName);
			
                        ContentObject co = handle.get(interest, TIME);
				

			byte[] data  =co.content();

                        data=this.decrypt(data,key,iv);

                        return data;

		} catch (Exception e) { 
			System.out.println(e);
			return null;
		}

	}

       /**
	*public int push(ContentName argName,byte[] content, String maID)
	*
	*This method asks for permission to send a data and saves it at the Content Store.
	*
	*@param argName name of interest data
	*@param content data for send
	*@param maID	ManagementAgent identificator
	*@return int 	if 1 we have permission to send if -1 no 
	*
	*/

	public boolean push(ContentName argName,byte[] content, String maID)throws IOException{
              
		try {

			SecretKey key=(SecretKey)MAData.get(maID);
			String d = new String(content, "UTF-8");
			repoData.put(argName,content);/*Save data in our Hashtable whit its name*/

                        String encrpt_argName=INTER.toString()+argName.toString();
                        byte [] crpt=this.encrypt(encrpt_argName.getBytes(), key, algorithm,iv);
                        encrpt_argName= bas.encodeToString(crpt);

                        argName=ContentName.fromURI(prefix+maID+meID+"/"+encrpt_argName);/*Interest's name*/

                        Interest interest = new Interest(argName);
                        ContentObject response =handle.get(interest, TIME);

                        byte[] data=this.decrypt(response.content(),key,iv);

                        /*Look for afirmative or negative reponse*/
                        if(data[0]==ACCEPT)return true;

                        return false;

                } catch (Exception e) {

                        System.out.println("Somethin wrong happens in push!!!!!!!!!!!!!!!!");
			System.out.println(e);
                        return false;

                }
        }


       /**
	*public boolean handleInterest(Interest interest)
	*
	*This method works different in case of pull interest or push interest 
	*If is a push interest it asks for an authorization to the application and expresses an interest if it confirms this 
	*If is a pull interest it asks for a content to the application and puts it at the Content Store
  	*
	*@param Interest which catch for analyze
	*@return boolean (without effect)
	*
	*/

	public boolean handleInterest(Interest interest){

		try{	
			String maID=new String();
                        String name_cont=interest.name().toString();
			/*In case of we unknow the interest procedence, analyce for the MA's name*/
                        if(name_cont.contains(BOOTSTRAP.toString())==false){
	
				maID=this.searchMaID(interest.name().toString().toCharArray());

                        }

			/*Special message at the start of the communication*/
                        if(name_cont.contains(BOOTSTRAP.toString())){
				this.sendMeid();
				return true;

			}

			/*Look for interest name and decode it if it is necesary*/
			ContentName contentN=this.filterName(name_cont,maID);
			if(name_cont.contains(KEY.toString())){

                                this.testKey(contentN, interest, maID);


                        }
                        /*If is the first message of push petition*/
                       else  if(contentN.toString().contains(INTER.toString())){

				String decrypted_name =contentN.toString().substring(INTER.length());
				contentN=ContentName.fromURI(decrypted_name);
				
				/*Wait for a petition with a Listener*/
				if(this.pushAuthorization(interest,contentN, maID)){

					SecretKey key=(SecretKey)MAData.get(maID);	
					byte [] crpt=this.encrypt(contentN.toString().getBytes(), key, algorithm,iv);
                        		String encrpt_argName= bas.encodeToString(crpt);
					ContentName argName=ContentName.fromURI(prefix+maID+meID+"/"+encrpt_argName);
		                        interest = new Interest(argName);
		                        MyInterestListener myIL = new MyInterestListener(argName,maID,application,key,iv);
		                        handle.expressInterest(interest, myIL); 
				}

			}else{
				/*Look for content in our Hashtable*/
                        	byte[]content =(byte[])repoData.get(contentN);

                                if(content == null){

                                        content = application.handleInterest(contentN, maID);
                                }else{
                                	repoData.remove(interest.name());
                                }

				SecretKey key=(SecretKey)MAData.get(maID);
				byte[] encrypt_content=this.encrypt(content, key, algorithm,iv);

                        	ContentObject co = ContentObject.buildContentObject (interest.name(),ContentType.DATA, encrypt_content, null, null, null, 0, null);
				/*Return asked data*/
                                if ( handle.put(co) == null) System.out.println("Error: ContentObject could not be put in the CS");
	                        maID=null;
			}

		} catch (Exception e) {

			System.out.println("Somethin wrong happens in handleInterest!!!!!!!!!!!!!!!!");
			System.out.println(e);
		}

		return true;
	}

}
