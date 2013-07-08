//==============================================================================
// Brief   : Management Entity
// Authors : Jaime Garcia <jgr@it.uc3m.es>
//           Iván Vidal Fernández <ividal@it.uc3m.es>
//           Daniel Corujo <dcorujo@av.it.pt>
//------------------------------------------------------------------------------
// Flexible Management Framework
//
// Copyright (C) 2013 Universidad Carlos III de Madrid
// Copyright (C) 2013 Universidade Aveiro
// Copyright (C) 2013 Instituto de Telecomunicações - Pólo Aveiro
//
// This software is distributed under a license. The full license
// agreement can be found in the file LICENSE in this distribution.
// This software may not be copied, modified, sold or distributed
// other than expressed in the named license agreement.
//
// This software is distributed without any warranty.
//==============================================================================

package org.ccnx.ccn.utils;

import java.lang.*;
import java.io.*;
import java.util.*;
import java.io.ByteArrayInputStream;
import java.io.IOException; 
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.logging.Level;

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
	private String maID;
	private String meID;
	private String managementCase;
	private String prefix;

	private Interest interest;
	private ApplicationME application;
	
	private Hashtable repoData;

	private static final byte ACCEPT=1;
        private static final byte REJECT=0;
	private static final long TIME=1000;
	private static final String INTER="/Interest";

       /**
	*public ManagementEntity (String networkPrefix, String managementCase, String meID, ApplicationME application)
	*
	*Constructor.  All String parameters must start with slash ("/")
	*
	*@param networkPrefix		net prefix
	*@param managementCase		net prefix
	*@param meID			ManagementEntity identificator
	*@param application		application which uses this API
	*/

	public ManagementEntity (String networkPrefix, String managementCase, String meID, ApplicationME application)throws Exception{


		this.networkPrefix = new String(networkPrefix);
		this.managementCase= new String(managementCase);
		this.meID= new String(meID);
		this.maID=null;
		prefix = new String(networkPrefix+managementCase);
		repoData = new Hashtable();
		this.application=application;
		handle = CCNHandle.open();
		ContentName filter = ContentName.fromURI(prefix+meID);                
		handle.registerFilter(filter, this);

	}

       /**
	*public byte[] pull(ContentName argName, String maID)
	*
	*This method asks for a data through an interest and returns it
	*
	*@param argName 	name of interest data
	*@param maID		ManagementAgent identificator
	*@return byte[] 	response content
	*/

	public byte[] pull(ContentName argName, String maID)throws IOException{

		try {	
			this.maID=new String(maID);

			argName=ContentName.fromURI(prefix+maID+meID+argName);/*Interest name*/
			interest = new Interest(argName);
			ContentObject co = handle.get(interest, TIME);

			return co.content();	

		} catch (Exception e) {
			System.out.println("Somethin wrong happens in pull!!!!!!!!!!!!!!!!");
			return null;
		}

	}

       /**
	*public int push(ContentName argName,byte[] content, String maID)
	*
	*This method asks for permission to send a data and saves it at our Hashtable.
	*
	*@param argName 	name of interest data
	*@param content 	data for send
	*@param maID		ManagementAgent identificator
	*@return int 		1 we have permission to send -1 no 
	*/

	public boolean push(ContentName argName,byte[] content, String maID)throws IOException{
              
		try {

                        this.maID=new String(maID);

                        ContentName argName2=ContentName.fromURI(prefix+meID+maID+argName);
			repoData.put(argName2,content);	/*Save data in our Hashtable whit its name*/

                        argName=ContentName.fromURI(prefix+maID+meID+INTER+argName);/*Interest name*/
                        interest = new Interest(argName);
                        ContentObject response = handle.get(interest, TIME);
			
			/*Look for afirmative or negative reponse*/
                        if(response.content()[0]==ACCEPT)return true;

                        return false;


		}catch (Exception e){

                        System.out.println("Somethin wrong happens in push!!!!!!!!!!!!!!!!");
                        return false;

                }

        }


       /**
	*public boolean handleInterest(Interest interest)
	*
	*This method works different in case of pull interest or push interest. If it is a push interest it asks for an 	   	   *authorization to the application and expresses an interest if it confirms this. If it is a pull interest it asks for a 	*content to the application and puts it at the Content Store
	*
	*@param Interest 	which catch for analyze
	*@return boolean 	(without effect)
	*/

	public boolean handleInterest(Interest interest){

		try{
                        int length_prefix =0;
                        String name_cont=interest.name().toString();

			/*In case of we unknow the interest procedence, analyce for the MA name*/
                        if(maID==null){
                                char [] name =(interest.name().toString()).toCharArray();
                                int i=prefix.length()+meID.length()+1;
                                String ma= "/";
                                while(name[i] !='/'){

                                        ma=ma+name[i];
                                        i++;

                                }
                                this.maID=ma;
                        }

			/*Look for prefix length*/
                        if(name_cont.contains(INTER.toString())){

                                length_prefix = prefix.length()+meID.length()+maID.length()+INTER.length();
                        }else{

                                length_prefix = prefix.length()+meID.length()+maID.length();
                        }

                        ContentName contentN=ContentName.fromURI(name_cont.substring(length_prefix));

                        /*If it is the first message of push petition*/
                        if(name_cont.contains(INTER.toString())){


		                ContentObject co_int;
		                byte [] acceptation = new byte[1];

				/*Ask for communication accepted*/
		                if(application.authorizeContent(contentN,maID)==true){
		                        acceptation[0]=ACCEPT;
		                }else{
		                        acceptation[0]=REJECT;
		                }

				co_int= ContentObject.buildContentObject (interest.name(),ContentType.DATA, acceptation, null, null, null, 0, null);
				/*Return accept or not message*/
				if ( handle.put(co_int) == null) System.out.println("Error: ContentObject could not be put in the CS");
				/*Wait for a petition with a Listener*/
				if(acceptation[0]==ACCEPT){

					ContentName argName=ContentName.fromURI(prefix+maID+meID+contentN);
		                        interest = new Interest(argName);
		                        MyInterestListener myIL = new MyInterestListener(argName,maID,application);
		                        handle.expressInterest(interest, myIL); 
					maID=null;
				}

			}

			/*If it is not the first message of push petition*/
			else{
				/*Look for content in our Hashtable*/
                        	byte[] content =(byte[])repoData.get(interest.name());

                                if(content == null){

                                        content = application.handleInterest(contentN, maID);
                                }else{

                                	repoData.remove(interest.name());
                                }

                        	ContentObject co = ContentObject.buildContentObject (interest.name(),ContentType.DATA, content, null, null, null, 0, null);
				/*Return asked data*/
                                if ( handle.put(co) == null) System.out.println("Error: ContentObject could not be put in the CS");
				maID=null;                        
			}

		} catch (Exception e) {

			System.out.println("Somethin wrong happens in handleInterest!!!!!!!!!!!!!!!!");
		}

		return true;
	}

}