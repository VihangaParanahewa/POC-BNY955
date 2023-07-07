package org.sample.poc;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import com.nimbusds.jwt.JWTClaimsSet;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.token.JWTTokenIssuer;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.sample.poc.dao.constants.SQLConstants;
import org.wso2.carbon.apimgt.impl.utils.APIMgtDBUtil;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinding;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class SampleJWTTokenIssuer extends JWTTokenIssuer {

    private static final Log log = LogFactory.getLog(SampleJWTTokenIssuer.class);
    private static final String TOKEN_BINDING_REF = "binding_ref";
    public static final String REQUEST_BINDING_TYPE = "request";

    public SampleJWTTokenIssuer() throws IdentityOAuth2Exception {
    }

    //This is the method which can get application attributes using consumer key with SQL JOIN
    @Override
    protected JWTClaimsSet handleTokenBinding(JWTClaimsSet.Builder jwtClaimsSetBuilder,
                                               OAuthTokenReqMessageContext tokReqMsgCtx) {

        String consumerKey = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getClientId();


        log.info("Client ID : " + consumerKey);

        String bindingRefValue = null;


        Connection connection = null;
        PreparedStatement prepStmt = null;
        ResultSet rs = null;

        try {
            connection = APIMgtDBUtil.getConnection();

            String query = SQLConstants.GET_APPLICATION_ATTRIBUTES_BY_CONSUMER_KEY;
            prepStmt = connection.prepareStatement(query);
            prepStmt.setString(1, consumerKey);

            rs = prepStmt.executeQuery();

            if (rs.next()) {
                String applicationId = rs.getString("APPLICATION_ID");
                String attributeName = rs.getString("NAME");
                String attributeValue = rs.getString("VALUE");
                bindingRefValue = attributeValue;
                log.info("Application ID : " + applicationId);
                log.info("Attribute Name : " + attributeName);
                log.info("Attribute Value : " + attributeValue);
            } else {
                log.error("No Application Found");
            }

        }catch (SQLException e) {
            log.error("Error while obtaining application details of the Consumer Key : " + consumerKey, e);
        } finally {
            APIMgtDBUtil.closeAllConnections(prepStmt, connection, rs);
        }

        setTokenBindingRef(tokReqMsgCtx, bindingRefValue);
        JWTClaimsSet sampleJWTClaimsSet = super.handleTokenBinding(jwtClaimsSetBuilder, tokReqMsgCtx);

        if (sampleJWTClaimsSet.getClaims().containsKey(TOKEN_BINDING_REF)) {
            log.info("binding_ref : " + sampleJWTClaimsSet.getClaims().get(TOKEN_BINDING_REF));
        }

        return sampleJWTClaimsSet;
    }

    //This is the method which can get application attributes using consumer key with two SQL
    //@Override
    protected JWTClaimsSet handleTokenBinding_(JWTClaimsSet.Builder jwtClaimsSetBuilder,
                                              OAuthTokenReqMessageContext tokReqMsgCtx) {
        String consumerKey = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getClientId();


        log.info("Client ID : " + consumerKey);

        String bindingRefValue = null;


        Connection connection = null;
        PreparedStatement prepStmt = null;
        ResultSet rs = null;

        try {
            connection = APIMgtDBUtil.getConnection();

            String query = SQLConstants.GET_APPLICATION_ID_BY_CONSUMER_KEY_SQL;
            prepStmt = connection.prepareStatement(query);
            prepStmt.setString(1, consumerKey);

            rs = prepStmt.executeQuery();

            if (rs.next()) {
                String applicationId = rs.getString("APPLICATION_ID");
                log.info("Application ID : " + applicationId);
                bindingRefValue = getApplicationAttributeValue(applicationId);
            } else {
                log.error("No Application Found");
            }

        }catch (SQLException e) {
            log.error("Error while obtaining application details of the Consumer Key : " + consumerKey, e);
        } finally {
            APIMgtDBUtil.closeAllConnections(prepStmt, connection, rs);
        }

        setTokenBindingRef(tokReqMsgCtx, bindingRefValue);
        JWTClaimsSet sampleJWTClaimsSet = super.handleTokenBinding(jwtClaimsSetBuilder, tokReqMsgCtx);

        return sampleJWTClaimsSet;
    }

    private void setTokenBindingRef(OAuthTokenReqMessageContext tokReqMsgCtx, String applicationAttributeValue) {

        if (tokReqMsgCtx != null && tokReqMsgCtx.getTokenBinding() == null) {

            tokReqMsgCtx.setTokenBinding(
                    new TokenBinding(REQUEST_BINDING_TYPE, applicationAttributeValue, applicationAttributeValue));
        }
    }


    private String getApplicationAttributeValue(String applicationId){

        String applicationAttributeValue = null;

        Connection connection = null;
        PreparedStatement prepStmt = null;
        ResultSet rs = null;

        try {
            connection = APIMgtDBUtil.getConnection();

            String query = SQLConstants.GET_APPLICATION_ATTRIBUTES_BY_APPLICATION_ID;
            prepStmt = connection.prepareStatement(query);
            prepStmt.setString(1, applicationId);

            rs = prepStmt.executeQuery();

            if (rs.next()) {
                String attributeName = rs.getString("NAME");
                applicationAttributeValue = rs.getString("VALUE");

                log.info("Attribute Name : " + attributeName);
                log.info("Attribute Value : " + applicationAttributeValue);
            } else {
                log.error("No Attributes Found");
            }

        }catch (SQLException e) {
            log.error("Error while obtaining application details of the Application ID : " + applicationId, e);
        } finally {
            APIMgtDBUtil.closeAllConnections(prepStmt, connection, rs);
        }

        return applicationAttributeValue;
    }
}
