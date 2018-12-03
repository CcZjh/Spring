package com.jwt.security.auth.login;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jwt.security.auth.HttpSessionRequestCache;

/**
 * 用户身份认证失败执行流程
 * @author 米斯特周
 *
 */
@Component
public class AwareAuthenticationFailHandler implements AuthenticationFailureHandler {
	
	private Logger logger = LoggerFactory.getLogger(getClass());

	private final ObjectMapper mapper;
	private final HttpSessionRequestCache httpSessionRequestCache;
	
	@Autowired
	public AwareAuthenticationFailHandler(ObjectMapper mapper, HttpSessionRequestCache httpSessionRequestCache) {
		this.mapper = mapper;
		this.httpSessionRequestCache = httpSessionRequestCache;
	}

	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException exception) throws IOException, ServletException {
		
		HttpServletRequest oldRequest = httpSessionRequestCache.getMatchingRequest(request, response);
		String targetUrl = oldRequest.getRequestURI();
		if (StringUtils.isBlank(targetUrl)) {
			// 抛出异常
		}
		if (logger.isDebugEnabled()) {
			logger.debug("The oldRequest targetUrl is:"+targetUrl);
		}

		response.setStatus(HttpStatus.UNAUTHORIZED.value());
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);

//	        response.getWriter();
		request.getRequestDispatcher(targetUrl).forward(request, response);
	}
	
	
}
