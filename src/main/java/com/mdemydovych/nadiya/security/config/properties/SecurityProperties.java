package com.mdemydovych.nadiya.security.config.properties;

import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

@Getter
@AllArgsConstructor
@ConfigurationProperties(prefix = "app.security")
public class SecurityProperties {

  private List<ClientConfig> clientConfigs;

  @Getter
  @AllArgsConstructor
  public static class ClientConfig {

    private String clientId;

    private String clientSecret;

    private String redirectUri;

    private ClientAuthenticationMethod authenticationMethod;

    private List<AuthorizationGrantType> grantTypes;
  }
}
