package oauth.client.vk.security;

import oauth.client.vk.security.oauth.CustomOAuth2AccessTokenResponseClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthenticationMethod;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        return new InMemoryClientRegistrationRepository(this.vkClientRegistration());
    }

    private ClientRegistration vkClientRegistration() {
        return ClientRegistration
                .withRegistrationId("vk")
                .clientId("51698275")
                .clientSecret("7D0RN6kiyUV2FZvoTK0n")
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationUri("https://oauth.vk.com/authorize")
                .tokenUri("https://oauth.vk.com/access_token")
                .scope("email", "phone_number", "friends", "photos")
                .userInfoAuthenticationMethod(AuthenticationMethod.QUERY)
                .userInfoUri("https://api.vk.com/method/users.get?v=5.89&fields=sex,city,country,photo_max,has_photo")
                .userNameAttributeName("response")
                .clientName("VK")
                .build();

    }

    @Bean
    public OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient() {
        return new CustomOAuth2AccessTokenResponseClient();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authorizeRequest -> authorizeRequest
                        .anyRequest().authenticated()
                )
                .oauth2Login((loginCustomizer) ->
                        loginCustomizer.tokenEndpoint(tokenEndpointConfig ->
                                tokenEndpointConfig.accessTokenResponseClient(accessTokenResponseClient())
                        )
                );

        return http.build();
    }
}
