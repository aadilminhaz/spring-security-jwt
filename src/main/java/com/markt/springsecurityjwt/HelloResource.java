package com.markt.springsecurityjwt;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import com.markt.springsecurityjwt.models.AuthenticationRequest;
import com.markt.springsecurityjwt.models.AuthenticationResponse;
import com.markt.springsecurityjwt.util.JWTUtil;

@Controller
public class HelloResource {

	@Autowired
	private AuthenticationManager authenticateManager;
	
	@Autowired
	private MyUserDetailsService userDetailsService;
	
	@Autowired
	private JWTUtil jwtTokenUtil;
	
	@RequestMapping(value={"/hello"}, method = RequestMethod.GET)
	@ResponseBody
	public String hello() {
		return "Hello World!";
	}
	
	@RequestMapping(value= {"/authenticate"}, method=RequestMethod.POST)
	@ResponseBody
	public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthenticationRequest authenticationRequest) throws Exception {
		try {
			authenticateManager.authenticate(new UsernamePasswordAuthenticationToken(authenticationRequest.getUsername(), authenticationRequest.getPassword()));
		} catch (BadCredentialsException e) {
			throw new Exception("Incorrect username or password");
		}
		
		final UserDetails userDetails = userDetailsService.loadUserByUsername(authenticationRequest.getUsername());
		
		final String jwt = jwtTokenUtil.generateToken(userDetails);
		return ResponseEntity.ok(new AuthenticationResponse(jwt));
	}
		
}
