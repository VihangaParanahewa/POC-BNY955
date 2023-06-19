package org.sample.poc;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import com.nimbusds.jwt.JWTClaimsSet;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.token.JWTTokenIssuer;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.apimgt.impl.dao.constants.SQLConstants;
import org.wso2.carbon.apimgt.impl.utils.APIMgtDBUtil;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class SampleJWTTokenIssuer extends JWTTokenIssuer {

    private static final Log log = LogFactory.getLog(SampleJWTTokenIssuer.class);


    public SampleJWTTokenIssuer() throws IdentityOAuth2Exception {
        super();
    }

    @Override
    protected JWTClaimsSet handleTokenBinding(JWTClaimsSet.Builder jwtClaimsSetBuilder,
                                              OAuthTokenReqMessageContext tokReqMsgCtx) {
        String consumerKey = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getClientId();


        log.info("Access token request with token request message context. Client ID" + consumerKey);


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
            log.error("Error while obtaining details of the Consumer Key : " + consumerKey, e);
        } finally {
            APIMgtDBUtil.closeAllConnections(prepStmt, connection, rs);
        }

        return super.handleTokenBinding(jwtClaimsSetBuilder, tokReqMsgCtx);
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
            log.error("Error while obtaining details of the Application Data : " + applicationId, e);
        } finally {
            APIMgtDBUtil.closeAllConnections(prepStmt, connection, rs);
        }
    }
}
