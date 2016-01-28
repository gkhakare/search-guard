/*
 * Copyright 2015 floragunn UG (haftungsbeschränkt)
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

package com.floragunn.searchguard.authentication.backend.simple;

import java.util.HashMap;
import java.util.Map;


import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang.StringUtils;
import org.elasticsearch.action.get.GetResponse;
import org.elasticsearch.client.Client;
import org.elasticsearch.client.transport.TransportClient;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.InetSocketTransportAddress;


import com.floragunn.searchguard.authentication.AuthException;
import com.floragunn.searchguard.authentication.User;
import com.floragunn.searchguard.authentication.backend.NonCachingAuthenticationBackend;
import com.floragunn.searchguard.util.ConfigConstants;

public class SettingsBasedAuthenticationBackend implements NonCachingAuthenticationBackend {
	
	protected final ESLogger log = Loggers.getLogger(this.getClass());
	static Client client = null;

    private final Settings settings;
    static Map<String, Client> pool = new HashMap<String, Client>();

    @Inject
    public SettingsBasedAuthenticationBackend(final Settings settings) {
        this.settings = settings;
    }

    @Override
    public User authenticate(final com.floragunn.searchguard.authentication.AuthCredentials authCreds) throws AuthException {
        final String user = authCreds.getUsername();
        final String clearTextPassword = authCreds.getPassword() == null?null:new String(authCreds.getPassword());
        authCreds.clear();
        
        String digest = settings.get(ConfigConstants.SEARCHGUARD_AUTHENTICATION_SETTINGSDB_DIGEST, null);
        final String storedPasswordOrDigest = settings.get(ConfigConstants.SEARCHGUARD_AUTHENTICATION_SETTINGSDB_USER + user, null);
        
        if(!StringUtils.isEmpty(clearTextPassword) && !StringUtils.isEmpty(storedPasswordOrDigest)) {
        
        	String passwordOrHash = clearTextPassword;
        	
	        if (digest != null) {
	
	            digest = digest.toLowerCase();
	
	            switch (digest) {
	
	                case "sha":
	                case "sha1":
	                	passwordOrHash = DigestUtils.sha1Hex(clearTextPassword);
	                    break;
	                case "sha256":
	                	passwordOrHash = DigestUtils.sha256Hex(clearTextPassword);
	                    break;
	                case "sha384":
	                	passwordOrHash = DigestUtils.sha384Hex(clearTextPassword);
	                    break;
	                case "sha512":
	                	passwordOrHash = DigestUtils.sha512Hex(clearTextPassword);
	                    break;
	
	                default:
	                	passwordOrHash = DigestUtils.md5Hex(clearTextPassword);
	                    break;
	            }
	
	        }
	
	        if (storedPasswordOrDigest.equals(passwordOrHash)) {
	            return new User(user);
	        }
	        if(log.isInfoEnabled()){
	        	log.info("User " + user + "is not authenticated with settings. Trying using auth key.................................................");
	        }
	        
	        
	      /*  log.info("", cause, params);*/
	        if(  validateUsingAuthKey(user, passwordOrHash) ){
	        	  if(log.isInfoEnabled()){
	        		  log.info("Use is authenticated using auth key.................................................");
	        	  }
	        	  return new User(user); 
	        }
	      
			
	        
        
        }

        throw new AuthException("No user " + user + " or wrong password (digest: " + (digest == null ? "plain/none" : digest) + ")");
    }

	private boolean validateUsingAuthKey(final String user, String passwordOrHash)
			 {
		try {
			Client client = getTransportClient();
			GetResponse response = client.prepareGet().putHeader("searchguard_transport_creds", getBase64KeyVaue()).setId(passwordOrHash).setIndex("searchguardauth").setType("authkey").execute().get();
			
			Map<String, Object> source = response.getSource();
			if(log.isInfoEnabled()){
				log.info("Returned data.................................................");
			}
			 
			if(source != null){
				   String userName = (String) source.get("user");
				   if(userName != null && userName.equals(user)){
					   log.info("User is authenticated using auth key: User: ", user);
					   return true;
				   }
			}
			
		} catch (Exception e) {
			log.error("Error occurred while fetching data for authentication using key.......................................", e);
			e.printStackTrace();
		}
		return false;
	}

	private Object getBase64KeyVaue() {
		String pass = settings.get("searchguard.authentication.settingsdb.user.admin");
		//String pass = "admin";
		String t = "admin:" + pass;
		 if(log.isInfoEnabled()){
			 log.info("Encoding string.............................................................." + t);
		 }
		
		byte[] encodeBase64 = Base64.encodeBase64(t.getBytes());
		String encodedString = new String(encodeBase64);
		if(log.isInfoEnabled()){
			log.info("Encoded password is:...." + encodedString);
		}
		return encodedString;
	}

	private Client getTransportClient() {
		log.info("Getting transport client fetching authentication data.................................................");
		String hostName = "localhost";
		int port = 9300;
		if(client == null){
			client = new TransportClient()
            .addTransportAddress(new InetSocketTransportAddress( hostName, port));
			
		}
		
		return client;
	
	}
	


}

