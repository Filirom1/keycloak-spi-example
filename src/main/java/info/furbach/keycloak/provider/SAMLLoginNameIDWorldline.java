/*
 * Copyright 2019 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package info.furbach.keycloak.provider;

import org.keycloak.protocol.saml.mappers.*;

import java.util.ArrayList;
import java.util.List;
import org.jboss.logging.Logger;
import org.keycloak.dom.saml.v2.assertion.NameIDType;
import org.keycloak.dom.saml.v2.protocol.ResponseType;
import org.keycloak.dom.saml.v2.protocol.ResponseType.RTChoiceType;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.provider.ProviderConfigProperty;

/**
 * SAML mapper to add a audience restriction into the assertion, to another
 * client (clientId) or to a custom URI. Only one URI is added, clientId
 * has preference over the custom value (the class maps OIDC behavior).
 *
 * @author rmartinc
 */
public class SAMLLoginNameIDWorldline extends AbstractSAMLProtocolMapper implements SAMLLoginResponseMapper {

    protected static final Logger logger = Logger.getLogger(SAMLAudienceProtocolMapper.class);

    public static final String PROVIDER_ID = "saml-nameid-worldline";

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<ProviderConfigProperty>();


    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "NameID";
    }

    @Override
    public String getDisplayCategory() {
        return "NameID";
    }

    @Override
    public String getHelpText() {
        return "Override NameID domain name with worldline.com";
    }

    @Override
    public ResponseType transformLoginResponse(ResponseType response,
            ProtocolMapperModel mappingModel, KeycloakSession session,
            UserSessionModel userSession, ClientSessionContext clientSessionCtx) {
        UserModel user = userSession.getUser();
        String attributeValue = user.getEmail().replaceAll("@.*", "@worldline.com");
        for (RTChoiceType rtChoiceType : response.getAssertions()) {
            NameIDType nameIDType = (NameIDType) rtChoiceType.getAssertion().getSubject().getSubType().getBaseID();
            nameIDType.setValue(attributeValue);
        }

        return response;
    }

}
