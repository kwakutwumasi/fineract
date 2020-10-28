/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.fineract.infrastructure.security.service;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.fineract.infrastructure.security.constants.TwoFactorConstants;
import org.apache.fineract.infrastructure.security.data.AliasCheckResponse;
import org.apache.fineract.infrastructure.security.exception.TOTPDeviceNotFoundException;
import org.apache.fineract.infrastructure.security.exception.TOTPServerAuthenticationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import com.google.gson.JsonObject;
import com.squareup.okhttp.OkHttpClient;

import retrofit.RestAdapter;
import retrofit.RetrofitError;
import retrofit.client.OkClient;

@Service
@Profile("twofactor")
public class TOTPServerTokenAuthenticationServiceImpl implements TOTPServerTokenAuthenticationService {

	private final TwoFactorConfigurationService twoFactorConfigurationService;
	private Map<String, AuthenticationData> directAuthenticationCache = new ConcurrentHashMap<>();
	
	@Autowired
	public TOTPServerTokenAuthenticationServiceImpl(TwoFactorConfigurationService twoFactorConfigurationService) {
		this.twoFactorConfigurationService = twoFactorConfigurationService;
	}
	
	private TOTPAuthenticationService totpAuthenticationService;
	private String url;
	
	private TOTPAuthenticationService getTOTPAuthenticationService() {
		if(twoFactorConfigurationService.getTOTPServerURL() == null)
			throw new TOTPServerAuthenticationException();
		
		if(totpAuthenticationService == null || 
				!twoFactorConfigurationService.getTOTPServerURL().equals(url)) {
			url = twoFactorConfigurationService.getTOTPServerURL();
			OkHttpClient client = new OkHttpClient();
			RestAdapter restAdapter = new RestAdapter.Builder()
					.setEndpoint(url).setClient(new OkClient(client)).build();
			totpAuthenticationService = restAdapter.create(TOTPAuthenticationService.class);
		}
		
		return totpAuthenticationService;
	}
	
	@Override
	public void authenticateDirectly(String username) {
		JsonObject jsonObject = new JsonObject();
		jsonObject.addProperty(TwoFactorConstants.TOTP_DEVICE_ID, username);
		AuthenticationData authenticationData = getAuthenticationData(username);
		jsonObject.add("authenticationData", authenticationData.getJsonObject());
		
		try {
			getTOTPAuthenticationService().authenticateDirect(jsonObject);
		} catch (RetrofitError e) {
			if(e.getResponse().getStatus()==404) {
				throw new TOTPDeviceNotFoundException();
			} else {
				throw new TOTPServerAuthenticationException();
			}
		}
	}

	@Override
	public void authenticate(String username, String password) {
		JsonObject jsonObject = new JsonObject();
		jsonObject.addProperty(TwoFactorConstants.TOTP_DEVICE_ID, username);
		jsonObject.addProperty(TwoFactorConstants.TOTP_OTP, password);
		
		try {
			getTOTPAuthenticationService().authenticate(jsonObject);
		} catch (RetrofitError e) {
			throw new TOTPServerAuthenticationException();
		}
	}

	@Override
	public String generateAuthenticationID(String username, String applicationName) {
		CompletableFuture.runAsync(this::pruneCache);
		AuthenticationData directAuthenticationData = getAuthenticationData(username);
		directAuthenticationData.getJsonObject().addProperty(TwoFactorConstants.TOTP_APPLICATION_NAME, applicationName);
		return directAuthenticationData.getJsonObject().get(TwoFactorConstants.TOTP_AUTHENTIATION_ID).getAsString();
	}

	@Override
	public AliasCheckResponse checkAlias(String username) {
		return getTOTPAuthenticationService().checkAlias(username);
	}

	private void pruneCache() {
		directAuthenticationCache.entrySet()
			.removeIf(entry->entry.getValue().created.plusMinutes(5)
					.compareTo(LocalDateTime.now())>0);
	}
	
	private AuthenticationData getAuthenticationData(String username) {
		return directAuthenticationCache
				.computeIfAbsent(username, key-> new AuthenticationData());
	}
	
	private SecureRandom secureRandom = new SecureRandom();

	class AuthenticationData {
		LocalDateTime created;
		private JsonObject jsonObject;

		AuthenticationData() {
			created = LocalDateTime.now();
			jsonObject = new JsonObject();
			jsonObject.addProperty(TwoFactorConstants.TOTP_APPLICATION_NAME, TwoFactorConstants.TOTP_DEFAULT_APPLICATION_NAME);
			jsonObject.addProperty(TwoFactorConstants.TOTP_AUTHENTIATION_ID, generateRandomID());
		}
		
		JsonObject getJsonObject() {
			return jsonObject ;
		}

		// 0 - 9 : 48
		// A - Z : 65
		
		String generateRandomID() {
			char[] randomID = new char[twoFactorConfigurationService.getTOTPAuthenticationIDLength()];
			for(int i=0;i<randomID.length;i++) {
				char c;
				if(secureRandom.nextInt()%2==0){
					c = (char) (48+(Math.abs(secureRandom.nextInt()%9)));
				} else {
					c = (char) (65+(Math.abs(secureRandom.nextInt()%25)));
				}
				randomID[i] = c;
			}
			return new String(randomID);
		}
	}
}
