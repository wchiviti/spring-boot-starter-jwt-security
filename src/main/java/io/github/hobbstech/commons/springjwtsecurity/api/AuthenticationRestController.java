package io.github.hobbstech.commons.springjwtsecurity.api;

import io.github.hobbstech.commons.springjwtsecurity.service.AuthenticationRequest;
import io.github.hobbstech.commons.springjwtsecurity.service.AuthenticationResponse;
import io.github.hobbstech.commons.springjwtsecurity.service.AuthenticationService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@CrossOrigin
@Api(tags = "Authentication/Login")
public class AuthenticationRestController {

    private final AuthenticationService authenticationService;

    public AuthenticationRestController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    @PostMapping(value = "/authenticate")
    @ApiOperation("Create an Authentication token or Login")
    public AuthenticationResponse createAuthenticationToken(@RequestBody AuthenticationRequest authenticationRequest) throws Exception {
        return authenticationService.authenticate(authenticationRequest);
    }

}
