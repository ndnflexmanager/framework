
package org.ccnx.ccn.utils;

import java.lang.*;
import java.io.*;
import java.util.*;
import java.io.ByteArrayInputStream;
import java.io.IOException; 
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.Key;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.logging.Level;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKey;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.IllegalBlockSizeException;

import org.ccnx.ccn.io.content.PublicKeyObject;
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


public class ManagementAgent implements CCNFilterListener {


	private String networkPrefix; 
	private CCNHandle handle;
	private String maID;
	private String meID;
	private String managementCase;
	private String prefix;

	private MAInterface application;
	
	private Hashtable repoData;

	private byte [] iv = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x10,0x11,0x12,0x13,0x14,0x15};

	private ccnBase64 bas;

	private SecretKey key;
	private PublicKey pKey;

	private static String algorithmCipher="AES/CBC/PKCS5Padding";

	private static final byte ACCEPT=1;
        private static final byte REJECT=0;
	private static final long TIME=17000;
	private static final String INTER="/Interest"; 
	private static final String BOOTSTRAP="/ME";
	private static final String KEY="/setKey";
	private static final String NONCE="/nonce";

       /**
	*public ManagementEntity (String networkPrefix, String managementCase, String meID, ApplicationME application)
	*
	*Constructor for bootstrapping  
	*All String parameters must start with slash ("/")
	*
	*@param networkPrefix		net's prefix
	*@param managementCase	        net's prefix
	*@param maID			ManagementAgent identificator
	*@param application		application which uses this API
	*
	*/

	public ManagementAgent (String networkPrefix, String managementCase, String maID, MAInterface application)throws Exception{


		this.networkPrefix = new String(networkPrefix);
		this.managementCase= new String(managementCase);
		this.maID= new String(maID);
		prefix = new String(networkPrefix+managementCase);
		this.application=application;
		repoData = new Hashtable();
		bas =new ccnBase64();
		handle = CCNHandle.open();
		ContentName filter = ContentName.fromURI(prefix+maID);                
		handle.registerFilter(filter, this);
		
		this.initiation();

	}

       /**
	*ManagementAgent (String networkPrefix, String managementCase, String maID, String meID, ApplicationMA application)
	*
	*Constructor without bootstrapping
	*All String parameters must start with slash ("/")
	*
	*@param networkPrefix		net's prefix
	*@param managementCase		net's prefix
	*@param maID			ManagementAgent identificator
	*@param meID			ManagementEntity identificator
	*@param application		application which uses this api
	*
	*/

	public ManagementAgent (String networkPrefix, String managementCase, String maID, String meID, MAInterface application)throws Exception{


		this.networkPrefix = new String(networkPrefix);
		this.managementCase= new String(managementCase);
		this.maID= new String(maID);
		this.meID= new String(meID);
		prefix = new String(networkPrefix+managementCase);
		this.application=application;
                repoData = new Hashtable();
		handle = CCNHandle.open();
		ContentName filter = ContentName.fromURI(prefix+maID);                
		handle.registerFilter(filter, this);

	}
	
       /**
        *private static byte[] encrypt(byte[] inpBytes, Key key, String xform,byte[] iv)
        *       
        *This function encrypt input data for SecretKey
        *
        *
        *@param inpBytes        bytes for encrytp
        *@param key             key which use for encrypt
        *@param xform           algorithm for encrypt
        *@param iv              
        *
        *@return byte[]         encrypt data
        *
        */

	private static byte[] encrypt(byte[] inpBytes, Key key, String xform,byte[] iv) throws Exception {

	   	 Cipher cipher = Cipher.getInstance(xform);
    		 cipher.init(Cipher.ENCRYPT_MODE, key,new IvParameterSpec(iv));
   	 	 return cipher.doFinal(inpBytes);
	}

       /**
        *private static byte[] encryptP(byte[] inpBytes, Key key, String xform)
        *       
        *This function encrypt input data for PublicKey
        *
        *
        *@param inpBytes        bytes for encrytp
        *@param key             key which use for encrypt
        *@param xform           algorithm for encrypt
        *
        *@return byte[]         encrypt data
        *
        */
	private static byte[] encryptP(byte[] inpBytes, Key key, String xform) throws Exception {

            	 Cipher cipherP = Cipher.getInstance(xform);
                 cipherP.init(Cipher.ENCRYPT_MODE, key);
                 return cipherP.doFinal(inpBytes);
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
		
		Cipher cipher = Cipher.getInstance(algorithmCipher);	
    		cipher.init(Cipher.DECRYPT_MODE,key,new IvParameterSpec(iv));
    		return cipher.doFinal(inpBytes);
  	}

       /**
	*private byte[] responseTest(ContentName contentN)
	*
	*This method reads the challenge and modifies the data to response it
	*
	*@param contenN		interest name which content the challenge
	*
	*@return byte[] 	encrypt challenge response
	*
	*/
	
	private byte[] responseTest(ContentName contentN) throws Exception{

                byte[] dataChallenge  = bas.decode(contentN.toString());
		dataChallenge=this.decrypt(dataChallenge,key,iv);

		int dataSend= ((int)dataChallenge[0])+1;
		dataChallenge[0]= ((byte)dataSend);

		return this.encrypt(dataChallenge,key,algorithmCipher,iv);
	}

       /**
	*private void askForMEID()throws Exception
	*
	*This method asks for meID to ME and takes the PublicKey info from ME that we use to send our SecretKey
	*
	*/
	private void askForMEID()throws Exception{

		ContentName argName=ContentName.fromURI(prefix+BOOTSTRAP);/*Interest name*/

                Interest interest = new Interest(argName);

                ContentObject co = handle.get(interest, TIME);
		pKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(co.content()));
		String stringKey = bas.encodeToString(pKey.getEncoded());
                char [] analyzeMEId = (co.name().toString()).toCharArray();

                if(meID==null){
                                String me= "/";

                                for(int i=prefix.length()+BOOTSTRAP.length()+1;i<analyzeMEId.length;i++){

                                        me=me+analyzeMEId[i];

                                }
                                this.meID=me;
                 }
		
	}

       /**
	*private void initiation()
	*	
	*This method is responsible of know about meID and creates our SecretKey which sends to ME
	*
	*/

	private void initiation()throws Exception{

		this.askForMEID();
		/*Generate key*/
                String stringKey="";

                try {
                        key = KeyGenerator.getInstance("AES").generateKey();
                }
                catch (Exception e) {}
		                
		/*Send key into an interest and wait for ack*/
		stringKey = bas.encodeToString(this.encryptP(key.getEncoded(),pKey,"RSA"));
		System.out.println("-*-*-*-*-*-*-*-*-*-EncodedKey"+stringKey);
                ContentName argNameKey=ContentName.fromURI(prefix+meID+maID+KEY+"/"+stringKey);/*Interest name*/
                Interest interest = new Interest(argNameKey);

                ContentObject co2 = handle.get(interest, TIME);
                if(co2.content()[0]==1){
                System.out.println("the key has arrived");
        
                }

	}

       /**
        *private ContentName filterName(String name_cont)
        *
        *This method filters interest name and decodes it if is necessary
        *
        *@param name_cont       interest name
        *
        *@return ContentName    filtered and decoded interest name
        *
        */

	private ContentName filterName(String name_cont)throws Exception{

                String decrypted_name = name_cont.substring(prefix.length()+meID.length()+maID.length());


                try{
                        byte[] crpt  = bas.decode(decrypted_name);
                        crpt=this.decrypt(crpt,key,iv);
                        decrypted_name=new String(crpt, "UTF-8");

                }catch(Exception e){

                }


                return ContentName.fromURI(decrypted_name);

        }

       /**
        *private boolean pushAuthorization(Interest interest,ContentName contentN)
        *
        *This function asks to the application for an authirization
        *
        *@param interest            interest which needs authorization
        *@param contentN            name of the data required
        *
        *@return boolean            true if the authorization is confirmed        
        */

	private boolean pushAuthorization(Interest interest,ContentName contentN)throws Exception{

                ContentObject co_int;
                byte [] acceptation = new byte[1];

                /*Ask for communication accepted*/
                if(application.authorizeContent(contentN)==true){
                    acceptation[0]=ACCEPT;
                }else{
                    acceptation[0]=REJECT;
                }

                byte [] accept=this.encrypt(acceptation, key, algorithmCipher,iv);

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
	*@return byte[] response's content
	*
	*/

	public byte[] pull(ContentName argName)throws IOException{

		try {
			byte [] crpt=this.encrypt(argName.toString().getBytes(), key, algorithmCipher,iv);
                        String encrpt_argName= bas.encodeToString(crpt);

                        argName=ContentName.fromURI(prefix+meID+maID+"/"+encrpt_argName);/*Interest's name*/
			Interest interest = new Interest(argName);
			ContentObject co = handle.get(interest, TIME);

                	byte[] data  =co.content();
			
                	data=this.decrypt(data,key,iv);

			return data;

		} catch (Exception e) {
			System.out.println("Somethin wrong happens in pull!!!!!!!!!!!!!!!!");
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
	*@return int 	if 1 we have permission to send if -1 no 
	*
	*/

	public boolean push(ContentName argName,byte[] content)throws IOException{

		try {
			repoData.put(argName,content);/*Save data in our Hashtable whit its name*/

			String encrpt_argName=INTER.toString()+argName.toString();
        		byte [] crpt=this.encrypt(encrpt_argName.getBytes(), key, algorithmCipher,iv);
                        encrpt_argName= bas.encodeToString(crpt);
                        argName=ContentName.fromURI(prefix+meID+maID+"/"+encrpt_argName);/*Interest's name*/

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
	*If is a pull interest it asks for a content to the application and puts it at the Content Store.
	*
	*@param Interest which catch for analyze
	*@return boolean (without effect)
	*
	*/

	public boolean handleInterest(Interest interest){
		
        	try{	
			/*Look for prefix length*/
			String name_cont=interest.name().toString();

			if(name_cont.contains(NONCE.toString())){
				int length_prefix = prefix.length()+meID.length()+maID.length()+NONCE.length();

				ContentName contentN=ContentName.fromURI(name_cont.substring(length_prefix));

                                ContentObject co = ContentObject.buildContentObject (interest.name(),ContentType.DATA, this.responseTest(contentN), null, null, null, 0, null);
                                /*Return asked data*/
                                if ( handle.put(co) == null) System.out.println("Error: ContentObject could not be put in the CS");
				
				return true;			
			}


			ContentName contentN=this.filterName(name_cont);

			/*If is the first message of push petition*/
			if(contentN.toString().contains(INTER.toString())){


				String decrypted_name =contentN.toString().substring(INTER.length());
                                contentN=ContentName.fromURI(decrypted_name);


                                /*Wait for a petition with a Listener*/
                                if(this.pushAuthorization(interest,contentN)){

                                        byte [] crpt=this.encrypt(contentN.toString().getBytes(), key, algorithmCipher,iv);
                                        String encrpt_argName= bas.encodeToString(crpt);
                                        ContentName argName=ContentName.fromURI(prefix+meID+maID+"/"+encrpt_argName);
                                        interest = new Interest(argName);
                                        MyInterestListener myIL = new MyInterestListener(argName,application,key,iv);
                                        handle.expressInterest(interest, myIL);
                                }

			}else{
				/*Look for content in our Hashtable*/
                                byte[] content =(byte[])repoData.get(contentN);

                                if(content == null){
                                content = application.handleInterest(contentN);

                                }else{

                                 repoData.remove(contentN);
                                }
				byte[] encrypted_content=this.encrypt(content, key, algorithmCipher,iv);
		
                                ContentObject co = ContentObject.buildContentObject (interest.name(),ContentType.DATA, encrypted_content, null, null, null, 0, null);
				/*Return asked data*/
				if ( handle.put(co) == null) System.out.println("Error: ContentObject could not be put in the CS");
			}

		} catch (Exception e) {
			
			 System.out.println("Somethin wrong happens in handleInterest!!!!!!!!!!!!!!!!");
			 System.out.println(e);
		}

		return true;
	}


}
