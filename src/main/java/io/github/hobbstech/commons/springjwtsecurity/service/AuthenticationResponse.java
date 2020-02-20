package io.github.hobbstech.commons.springjwtsecurity.service;

import lombok.Data;

@Data
public class AuthenticationResponse {

    private final String jwtToken;

}
