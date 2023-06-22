package org.sample.poc;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import com.nimbusds.jwt.JWTClaimsSet;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
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

    public SampleJWTTokenIssuer() throws IdentityOAuth2Exception {
    }

    @Override
    protected JWTClaimsSet createJWTClaimSet(OAuthAuthzReqMessageContext authAuthzReqMessageContext, OAuthTokenReqMessageContext tokenReqMessageContext, String consumerKey) throws IdentityOAuth2Exception
    {
        JWTClaimsSet jwtClaimsSet = super.createJWTClaimSet(authAuthzReqMessageContext, tokenReqMessageContext, consumerKey);
        JWTClaimsSet sampleJWTClaimsSet = this.handleTokenBinding(new JWTClaimsSet.Builder(), tokenReqMessageContext);
        return jwtClaimsSet;
    }

    //This is the method which can get application attributes using consumer key with SQL JOIN
    @Override
    protected JWTClaimsSet handleTokenBinding(JWTClaimsSet.Builder jwtClaimsSetBuilder,
                                               OAuthTokenReqMessageContext tokReqMsgCtx) {
        String consumerKey = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getClientId();


        log.info("Client ID : " + consumerKey);


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

        return null;
    }

    //This is the method which can get application attributes using consumer key with two SQL
    //@Override
    protected JWTClaimsSet handleTokenBinding_(JWTClaimsSet.Builder jwtClaimsSetBuilder,
                                              OAuthTokenReqMessageContext tokReqMsgCtx) {
        String consumerKey = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getClientId();


        log.info("Client ID : " + consumerKey);


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
                getApplicationAttribute(applicationId);
            } else {
                log.error("No Application Found");
            }

        }catch (SQLException e) {
            log.error("Error while obtaining application details of the Consumer Key : " + consumerKey, e);
        } finally {
            APIMgtDBUtil.closeAllConnections(prepStmt, connection, rs);
        }

        return null;
    }

    private void handleException(String msg, Throwable t) throws APIManagementException {
        log.error(msg, t);
        throw new APIManagementException(msg, t);
    }

    private void getApplicationAttribute(String applicationId){
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
                String attributeValue = rs.getString("VALUE");
                log.info("Attribute Name : " + attributeName);
                log.info("Attribute Value : " + attributeValue);
            } else {
                log.error("No Attributes Found");
            }

        }catch (SQLException e) {
            log.error("Error while obtaining application details of the Application ID : " + applicationId, e);
        } finally {
            APIMgtDBUtil.closeAllConnections(prepStmt, connection, rs);
        }
    }
}
