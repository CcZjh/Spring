package com.jwt.security.auth;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.PortResolver;
import org.springframework.security.web.PortResolverImpl;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Component;

/**
 * 缓存请求类
 * 实现 RequestCache 接口
 * 
 * @author 米斯特周
 *
 */
@Component
public class HttpSessionRequestCache implements RequestCache {
	
	protected final Logger logger = LoggerFactory.getLogger(getClass());
	
	static final String SAVED_REQUEST = "SPRING_SECURITY_SAVED_REQUEST";
	
	private PortResolver portResolver = new PortResolverImpl();
	private boolean createSessionAllowed = true;
	private RequestMatcher requestMatcher =AnyRequestMatcher.INSTANCE;

	/**
	 * 保存请求缓存
	 */
	@Override
	public void saveRequest(HttpServletRequest request, HttpServletResponse response) {
		
		if (requestMatcher.matches(request)) {
			DefaultSavedRequest savedRequest = new DefaultSavedRequest(request,
					portResolver);
 
			if (createSessionAllowed || request.getSession(false) != null) {
				// Store the HTTP request itself. Used by
				// AbstractAuthenticationProcessingFilter
				// for redirection after successful authentication (SEC-29)
				request.getSession().setAttribute(SAVED_REQUEST, savedRequest);
				logger.debug("DefaultSavedRequest 添加 session: " + savedRequest);
			}
		}
		else {
			logger.debug("请求没有被保存!");
		}
		
	}

	/**
	 * 获取请求缓存
	 */
	@Override
	public SavedRequest getRequest(HttpServletRequest request, HttpServletResponse response) {
		
		HttpSession session = request.getSession(false);
		 
		if (session != null) {
			return (SavedRequest) session.getAttribute(SAVED_REQUEST);
		}
 
		return null;
	}

	/**
	 * 获取请求缓存并删除之前的session
	 * 
	 * @return HttpServletRequest
	 */
	@Override
	public HttpServletRequest getMatchingRequest(HttpServletRequest request, HttpServletResponse response) {
		DefaultSavedRequest defaultSavedRequest = (DefaultSavedRequest) getRequest(request, response);
		
		if (defaultSavedRequest == null) {
			return null;
		}
		
		if (!defaultSavedRequest.doesRequestMatch(request, portResolver)) {
			logger.info("请求不匹配!");
			return null;
		}
		
		removeRequest(request, response);
		
		return new HttpServletRequestWrapper(request);
	}

	/**
	 * 删除请求缓存
	 */
	@Override
	public void removeRequest(HttpServletRequest request, HttpServletResponse response) {
		HttpSession session = request.getSession(false);
		if (session != null) {
			logger.info("删除session中的原始请求!");
			session.removeAttribute(SAVED_REQUEST);
		}
	}

}
