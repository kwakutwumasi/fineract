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

import java.util.List;
import org.apache.fineract.infrastructure.core.api.JsonCommand;
import org.apache.fineract.infrastructure.security.data.OTPDeliveryMethod;
import org.apache.fineract.infrastructure.security.data.OTPRequest;
import org.apache.fineract.infrastructure.security.domain.TFAccessToken;
import org.apache.fineract.useradministration.domain.AppUser;

public interface TwoFactorService {

    List<OTPDeliveryMethod> getDeliveryMethodsForUser(AppUser user);

    OTPRequest createNewOTPToken(AppUser user, String deliveryMethodName, boolean extendedAccessToken);

    TFAccessToken createAccessTokenFromOTP(AppUser user, String otpToken, String type);

    void validateTwoFactorAccessToken(AppUser user, String token);

    TFAccessToken fetchAccessTokenForUser(AppUser user, String token);

    TFAccessToken invalidateAccessToken(AppUser user, JsonCommand command);

}
