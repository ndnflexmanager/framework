//==============================================================================
// Brief   : Interest Listener
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
        private ApplicationME applicationMe;
	private ApplicationMA applicationMa;

	/**
	 *public MyInterestListener(ContentName argName, String maID, ApplicationME application)
	 *
	 *Constructor. For ME.
	 *
	 *@param argName		data's name
	 *@param maID		MA's id 
	 *@param application	application which uses this api
	 */

        public MyInterestListener(ContentName argName, String maID, ApplicationME application){

                this.argName=argName;
                this.maID=maID;
                applicationMe=application;


        }

	/**
	 *public MyInterestListener(ContentName argName, ApplicationMA application)
	 *
	 *Constructor. For MA.
	 *
	 *@param argName		data's name
	 *@param application	application which uses this api
	 */

	public MyInterestListener(ContentName argName, ApplicationMA application){

                this.argName=argName;
                this.maID=null;
                applicationMa=application;


        }

	/**
	 * public Interest handleContent(ContentObject result, Interest interest)
	 *
	 *This function catch the interest and 
	 *
	 *@param result		interest's data
	 *@param interest	interest to be catch
	 *
	 *@result Interest	(without effect)
	 */

         public Interest handleContent(ContentObject result, Interest interest) {
                try{
                        byte []data=result.content();

			if(maID==null){

				applicationMa.handleContent(argName, data);
			}else{
                  
	      			applicationMe.handleContent(argName, data,maID);
			}
                }catch(Exception e){

                }

                 return(null);
        }

}

