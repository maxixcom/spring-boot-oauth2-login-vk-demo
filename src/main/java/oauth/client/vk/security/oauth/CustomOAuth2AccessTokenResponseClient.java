package oauth.client.vk.security.oauth;

import oauth.client.vk.security.vk.VkOAuth2AccessTokenResponse;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequestEntityConverter;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.util.Assert;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

public class CustomOAuth2AccessTokenResponseClient implements OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> {
    private static final String INVALID_TOKEN_RESPONSE_ERROR_CODE = "invalid_token_response";
    private final OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> delegate;
    private final RestOperations restOperations;
    private final OAuth2AuthorizationCodeGrantRequestEntityConverter requestEntityConverter = new OAuth2AuthorizationCodeGrantRequestEntityConverter();

    public CustomOAuth2AccessTokenResponseClient() {
        this.delegate = new DefaultAuthorizationCodeTokenResponseClient();

        RestTemplate restTemplate = new RestTemplate();
        restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
        this.restOperations = restTemplate;

    }

    @Override
    public OAuth2AccessTokenResponse getTokenResponse(OAuth2AuthorizationCodeGrantRequest authorizationCodeGrantRequest) {
        if (authorizationCodeGrantRequest.getClientRegistration().getRegistrationId().equals("vk")) {
            return getTokenResponseVk(authorizationCodeGrantRequest);
        }
        return delegate.getTokenResponse(authorizationCodeGrantRequest);
    }

    private OAuth2AccessTokenResponse getTokenResponseVk(OAuth2AuthorizationCodeGrantRequest authorizationCodeGrantRequest) {

        Assert.notNull(authorizationCodeGrantRequest, "authorizationCodeGrantRequest cannot be null");
        RequestEntity<?> request = this.requestEntityConverter.convert(authorizationCodeGrantRequest);
        ResponseEntity<VkOAuth2AccessTokenResponse> response = getResponse(request);

        VkOAuth2AccessTokenResponse vkTokenResponse = response.getBody();

        Assert.notNull(vkTokenResponse,
                "The authorization server responded to this Authorization Code grant request with an empty body; as such, it cannot be materialized into an VkOAuth2AccessTokenResponse instance. Please check the HTTP response code in your server logs for more details.");

        OAuth2AccessTokenResponse.Builder builder = OAuth2AccessTokenResponse.withToken(vkTokenResponse.getAccessToken())
                .tokenType(OAuth2AccessToken.TokenType.BEARER)
                .expiresIn(vkTokenResponse.getExpiresIn())
                .additionalParameters(Map.of("user_id", vkTokenResponse.getUserId()))
                .scopes(authorizationCodeGrantRequest.getClientRegistration().getScopes());

        return builder.build();
    }


    private ResponseEntity<VkOAuth2AccessTokenResponse> getResponse(RequestEntity<?> request) {
        try {
            return this.restOperations.exchange(request, VkOAuth2AccessTokenResponse.class);

        } catch (RestClientException ex) {
            OAuth2Error oauth2Error = new OAuth2Error(INVALID_TOKEN_RESPONSE_ERROR_CODE,
                    "An error occurred while attempting to retrieve the OAuth 2.0 Access Token Response: "
                            + ex.getMessage(),
                    null);
            throw new OAuth2AuthorizationException(oauth2Error, ex);
        }
    }
}
