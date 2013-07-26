package org.ccnx.ccn.utils;

import java.lang.*;
import java.io.*;
import java.util.*;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import org.ccnx.ccn.CCNHandle;
import org.ccnx.ccn.CCNInterestListener;
import org.ccnx.ccn.config.SystemConfiguration;
import org.ccnx.ccn.protocol.ContentName;

/**
 *Interfaz for  ManagementAgent application
 */

public interface MAInterface{

/**
 *public byte[] handleInterest(ContentName filter);
 *
 *Receives the data name which need to send and returns it
 *
 *@param filter data name
 *@return byte[] data in byte Array
 */
public byte[] handleInterest(ContentName filter);

/**
 *public boolean authorizeContent(ContentName filter);
 *
 *Authorizes or not to express an interest for do push petition
 *
 *@param filter data name
 *@return boolean true if it authorizes, otherwise false
 */
public boolean authorizeContent(ContentName filter);

/**
 *public void handleContent(ContentName filter,byte[] content);
 *
 *Handles the data after push petition
 * 
 *@param filter 		data name
 *@param content		data content		
 *@return boolean  	true if it authorizes, otherwise false
 *
 */
public void handleContent(ContentName filter,byte[] content) throws Exception;

}
