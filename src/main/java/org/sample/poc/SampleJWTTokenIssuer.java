package org.sample.poc;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import com.nimbusds.jwt.JWTClaimsSet;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.token.JWTTokenIssuer;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.sample.poc.dao.constants.SQLConstants;
import org.wso2.carbon.apimgt.impl.utils.APIMgtDBUtil;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class SampleJWTTokenIssuer extends JWTTokenIssuer {

    private static final Log log = LogFactory.getLog(SampleJWTTokenIssuer.class);

    private static final String Attribute_Name = "renewWithoutRevokingExistingEnabled";

    public SampleJWTTokenIssuer() throws IdentityOAuth2Exception {
    }

    //This is the method which can get application attributes using consumer key with SQL JOIN
    @Override
    protected JWTClaimsSet handleTokenBinding(JWTClaimsSet.Builder jwtClaimsSetBuilder,
                                               OAuthTokenReqMessageContext tokReqMsgCtx) {

        String consumerKey = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getClientId();
        if (log.isDebugEnabled()) {
            log.debug("Client ID : " + consumerKey);
        }

        boolean applicationAttributeValue = getApplicationAttributeValue(consumerKey);

        if(applicationAttributeValue) {
           super.handleTokenBinding(jwtClaimsSetBuilder, tokReqMsgCtx);
        }

        return jwtClaimsSetBuilder.build();
    }


    private boolean getApplicationAttributeValue(String consumerKey) {
        boolean applicationAttributeValue = false;

        try (Connection connection = APIMgtDBUtil.getConnection()) {

            String query = SQLConstants.GET_APPLICATION_ATTRIBUTES_BY_CONSUMER_KEY;
            try (PreparedStatement prepStmt = connection.prepareStatement(query)) {
                prepStmt.setString(1, consumerKey);
                prepStmt.setString(2, Attribute_Name);
                try (ResultSet rs = prepStmt.executeQuery()) {

                    if (rs.next()) {
                        int applicationId = rs.getInt("APPLICATION_ID");
                        String attributeName = rs.getString("NAME");
                        String attributeValue = rs.getString("VALUE");
                        applicationAttributeValue = Boolean.parseBoolean(attributeValue);
                        if (log.isDebugEnabled()) {
                            log.debug("Application ID : " + applicationId);
                            log.debug("Attribute Name : " + attributeName);
                            log.debug("Attribute Value : " + attributeValue);
                        }
                    } else {
                        if (log.isDebugEnabled()) {
                            log.debug("No Attribute Found For The Application");
                        }
                    }
                }
            }
        } catch (SQLException e) {
            log.error("Error while obtaining application details of the Consumer Key : " + consumerKey, e);
        }
        return applicationAttributeValue;
    }
}
