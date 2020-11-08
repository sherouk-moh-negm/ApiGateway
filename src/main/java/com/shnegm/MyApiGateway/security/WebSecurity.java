package com.shnegm.MyApiGateway.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

@Configuration
@EnableWebSecurity
public class WebSecurity extends WebSecurityConfigurerAdapter {
	public WebSecurity(Environment env) {
		this.env = env;
	}


	@Value("${login.url}")
	private String loginUrl;
	@Value("${registeration.url}")
	private String registerationUrl;
	@Value("${h2ConsoleUrl.url}")
	private String h2ConsoleUrl;
	@Autowired
	Environment env;
	

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// we should disable Cross-Site Request Forgery to only enable the requests that
		// have auth token
		http.csrf().disable();
		http.headers().frameOptions().disable();

		/*
		 * the bellow line to make our api stateless: and stateless means: when the
		 * client app starts to communicate with server app there is http session and
		 * cookies created and this session is uniquely identify the client app so if
		 * there is multiple client app communicating this server api so there is diff
		 * created http sessions for each client so those sessions and cookies can cache
		 * some info from the request and this make our authorization header which
		 * contains JWT token also cached so if we don't provide this token the request
		 * will still authorized from the prev call and we don't need that we need to re
		 * authorized every http request and also because there is some calls like sign
		 * up and login we don't need the request to be authorized so we use stateless
		 * to tell our api service to not create sessions and will permit all for (http post) login
		 * and sign up calls and h2 console for all http calls type
		 * then any other requests should be authenticated 
		 */
		http.authorizeRequests()
		.antMatchers(h2ConsoleUrl).permitAll()
		.antMatchers(HttpMethod.POST, registerationUrl).permitAll()
		.antMatchers(HttpMethod.POST, loginUrl).permitAll()
		.anyRequest().authenticated()
		.and()
		.addFilter(new AuthorizationFilter(authenticationManager(),env));
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
		/* then we should create filter to authenticate valid jwt token but this time it will be basic authication filter 
		 * not UsernamePasswordAuthenticationFilter as the user ms*/

	}

}
