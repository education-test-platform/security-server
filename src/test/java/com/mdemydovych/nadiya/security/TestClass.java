package com.mdemydovych.nadiya.security;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

public class TestClass {

  @Test
  void shouldClass() {
        try {
      String CLIENT_ID = "articles-client";
      String CLIENT_SECRET = "321123";

      String encodeBytes  = Base64.getEncoder().encodeToString((CLIENT_ID + ":" + CLIENT_SECRET).getBytes());

      HttpClient client = HttpClient.newBuilder().build();
      HttpRequest request = HttpRequest.newBuilder()
          .uri(URI.create("http://localhost:9292/oauth2/token"))
          .header("Content-Type", "application/x-www-form-urlencoded")
          .header("Authorization", "Basic " + encodeBytes )
          .POST(HttpRequest.BodyPublishers.ofString("grant_type=jwt_bearer"))
          .build();

      HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
      System.out.println(response.body());
    }
    catch(Exception e) {
      System.out.println(e);
    }
  }
}
