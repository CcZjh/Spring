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
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import com.alibaba.fastjson.JSONObject;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.jwt.security.auth.HttpSessionRequestCache;
import com.jwt.security.model.UserContext;
import com.jwt.security.model.token.AccessToken;
import com.jwt.security.model.token.Token;
import com.jwt.security.model.token.TokenFactory;

/**
 * 用户身份认证成功执行流程
 * 
 * @author 米斯特周
 *
 */
@Component
public class AwareAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
	
	private Logger logger = LoggerFactory.getLogger(getClass());

	private final ObjectMapper mapper;
	private final TokenFactory tokenFactory;

	private final HttpSessionRequestCache httpSessionRequestCache;

	@Autowired
	public AwareAuthenticationSuccessHandler(final ObjectMapper mapper, final TokenFactory tokenFactory,
			final HttpSessionRequestCache httpSessionRequestCache) {
		this.mapper = mapper;
		this.tokenFactory = tokenFactory;
		this.httpSessionRequestCache = httpSessionRequestCache;
	}

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {

		HttpServletRequest oldRequest = httpSessionRequestCache.getMatchingRequest(request, response);
		String targetUrl = oldRequest.getRequestURI();
		if (StringUtils.isBlank(targetUrl)) {
			// 抛出异常
		}
		if (logger.isDebugEnabled()) {
			logger.debug("The oldRequest targetUrl is:"+targetUrl);
		}

		UserContext userContext = (UserContext) authentication.getPrincipal();

		AccessToken accessToken = tokenFactory.createAccessToken(userContext);
		Token refreshToken = tokenFactory.createRefreshToken(userContext);

		JSONObject tokenMap = new JSONObject();
		tokenMap.put("claims", accessToken.getClaims());
		tokenMap.put("token", accessToken.getToken());
		tokenMap.put("refreshToken", refreshToken.getToken());

		response.setStatus(HttpStatus.OK.value());
		response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
//		mapper.writeValue(response.getWriter(), tokenMap);
		request.setAttribute("tokenMap", tokenMap);
		request.getRequestDispatcher(targetUrl).forward(request, response);
	}

}
