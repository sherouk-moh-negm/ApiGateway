package com.shnegm.MyApiGateway.security;

import java.io.IOException;
import java.util.ArrayList;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import io.jsonwebtoken.Jwts;

public class AuthorizationFilter extends BasicAuthenticationFilter{
	Environment env;
	public AuthorizationFilter(AuthenticationManager authenticationManager,Environment env) {
		super(authenticationManager);
		this.env=env;
	}
	@Override
	protected void doFilterInternal(HttpServletRequest req,HttpServletResponse res,
			FilterChain chain) throws IOException, ServletException {
		//Authorization must come from env that passed from the constructor
		String authorizationHeader=req.getHeader(env.getProperty("authorization.token.header.name"));
		if(authorizationHeader==null ||  !authorizationHeader.startsWith(env.getProperty("authorization.token.header.prefix"))) {
			chain.doFilter(req, res);
			return;
		}
		UsernamePasswordAuthenticationToken auth=getAuthentication(req);
		SecurityContextHolder.getContext().setAuthentication(auth);
		chain.doFilter(req, res);
	}
	private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest req) {
		String authorizationHeader=req.getHeader(env.getProperty("authorization.token.header.name"));
		if(authorizationHeader==null ) {
			return null;
		}
		String token =authorizationHeader.replace(env.getProperty("authorization.token.header.prefix"), "");
		String userId=Jwts.parser()
				.setSigningKey(env.getProperty("token.secret"))
				.parseClaimsJws(token)
				.getBody()
				.getSubject();
		
		if(userId==null ) {
			return null;
		}		
		return new UsernamePasswordAuthenticationToken(userId,null,new ArrayList<>());
	}

	
}
