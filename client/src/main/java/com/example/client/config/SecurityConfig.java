package com.example.client.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
public class SecurityConfig {

//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        http
//                .authorizeHttpRequests(auth -> auth
//                        .anyRequest()
//                        .authenticated()
//                )
//                .oauth2Login(Customizer.withDefaults());
//        return http.build();
//    }

//    @Bean
//    public ClientRegistrationRepository clientRegistrationRepository() {
//        var client1 = ClientRegistration.withRegistrationId("auth-server")
//                .clientId("client")
//                .clientSecret("secret")
//                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//                .redirectUri("http://localhost:9000/login/oauth2/code/auth-server")

    /// /                .tokenUri("http://localhost:9000/oauth2/token")
//                .scope(OidcScopes.OPENID)
//                .build();
//        return new InMemoryClientRegistrationRepository(client1);
//    }

//    @Bean
//    public OAuth2AuthorizedClientManager authorizedClientManager(
//            ClientRegistrationRepository clientRegistrationRepository,
//            OAuth2AuthorizedClientRepository authorizedClientRepository
//    ) {
//        var provider = OAuth2AuthorizedClientProviderBuilder.builder()
//                .clientCredentials()
//                .build();
//        var clientManager = new DefaultOAuth2AuthorizedClientManager(
//                clientRegistrationRepository,
//                authorizedClientRepository);
//        clientManager.setAuthorizedClientProvider(provider);
//        return clientManager;
//    }
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, ClientRegistrationRepository clientRegistrationRepository) throws Exception {
        String baseUri = OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI;
        var resolver = new DefaultOAuth2AuthorizationRequestResolver(clientRegistrationRepository, baseUri);
        resolver.setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce());
        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/")
                        .permitAll()
                        .anyRequest()
                        .authenticated()
                )
                .oauth2Login(oauth2Login -> {
                    oauth2Login.loginPage("/oauth2/authorization/oidc-client");
                    oauth2Login.authorizationEndpoint(authorizationEndpoint ->
                            authorizationEndpoint.authorizationRequestResolver(resolver)
                    );
                })
                .oauth2Client(withDefaults());
        return http.build();
    }

}