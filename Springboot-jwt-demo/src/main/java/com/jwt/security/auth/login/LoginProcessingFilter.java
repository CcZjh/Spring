package com.jwt.security.auth.login;

import java.io.IOException;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import com.jwt.security.auth.HttpSessionRequestCache;
import com.jwt.security.exceptions.AuthMethodNotSupportedException;
import com.jwt.utils.RequestStreamUtil;

/**
 * 登录过滤器
 * 
 * @author 米斯特周
 *
 */
public class LoginProcessingFilter extends AbstractAuthenticationProcessingFilter {
	
	private Logger logger = LoggerFactory.getLogger(getClass());

	private final AuthenticationSuccessHandler successHandler;
	private final AuthenticationFailureHandler failureHandler;
	private final HttpSessionRequestCache  httpSessionRequestCache ;

	@Autowired
	public LoginProcessingFilter(String defaultProcessUrl, AuthenticationSuccessHandler successHandler,
			AuthenticationFailureHandler failureHandler, HttpSessionRequestCache  httpSessionRequestCache ) {
		super(defaultProcessUrl);
		this.successHandler = successHandler;
		this.failureHandler = failureHandler;
		this.httpSessionRequestCache  = httpSessionRequestCache ;
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {
		
		if (!HttpMethod.POST.name().equals(request.getMethod())) {
			if (logger.isDebugEnabled()) {
				logger.debug("Authentication method not support. Request method:"+request.getMethod());
			}
			throw new AuthMethodNotSupportedException("Authentication method not support");
		}
		
		// save Authentication request by RequestCache
		httpSessionRequestCache .saveRequest(request, response);
		
		// receive user information by inputStream(io)
		Map<String, String> map = RequestStreamUtil.toMap(request);
		String username = map.get("username");
		String password = map.get("password");
		
		LoginRequest loginRequest = new LoginRequest(username, password);
		if (StringUtils.isBlank(loginRequest.getUsername()) || StringUtils.isBlank(loginRequest.getPassword())) {
			throw new AuthenticationServiceException("User's username or password not Provided");
		}
		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username,
				password);
		return this.getAuthenticationManager().authenticate(token);
	}

	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		
		successHandler.onAuthenticationSuccess(request, response, authResult);
	}
	
	@Override
	protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException failed) throws IOException, ServletException {

		failureHandler.onAuthenticationFailure(request, response, failed);
	}
}
