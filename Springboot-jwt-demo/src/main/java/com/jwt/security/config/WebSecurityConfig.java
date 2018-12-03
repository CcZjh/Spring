package com.jwt.security.config;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Configurable;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.google.common.collect.Lists;
import com.jwt.security.RestAuthenticationEntryPoint;
import com.jwt.security.auth.HttpSessionRequestCache;
import com.jwt.security.auth.login.LoginAuthenticationProvider;
import com.jwt.security.auth.login.LoginProcessingFilter;
import com.jwt.security.auth.token.SkipPathRequestMatcher;
import com.jwt.security.auth.token.TokenAuthenticationProcessFilter;
import com.jwt.security.auth.token.TokenAuthenticationProvider;
import com.jwt.security.auth.token.extractor.TokenExtractor;

/**
 * security 核心配置类 
 * 过滤器开始类
 * @author 米斯特周
 */
/**
 * 类 Authentication 保存的是身份认证信息。 类 AuthenticationProvider 提供身份认证途径。 类
 * AuthenticationManager 保存的 AuthenticationProvider 集合，并调用
 * AuthenticationProvider 进行身份认证。
 */
@Configurable
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	public static final String TOKEN_HEADER_PARAM = "X-Authorization";
	private static final String FORM_BASED_LOGIN_ENTRY_POINT = "/api/login";
	private static final String TOKEN_BASED_AUTH_ENTRY_POINT = "/api/**";

	private final RestAuthenticationEntryPoint authenticationEntryPoint;
	private final AuthenticationSuccessHandler successHandler;
	private final AuthenticationFailureHandler failureHandler;
	private final LoginAuthenticationProvider loginAuthenticationProvider;
	private final TokenAuthenticationProvider tokenAuthenticationProvider;
	private final HttpSessionRequestCache httpSessionRequestCache;
	private final TokenExtractor tokenExtractor;

	@Autowired
	public WebSecurityConfig(RestAuthenticationEntryPoint authenticationEntryPoint,
			AuthenticationSuccessHandler successHandler, AuthenticationFailureHandler failureHandler,
			LoginAuthenticationProvider loginAuthenticationProvider, HttpSessionRequestCache httpSessionRequestCache,
			TokenExtractor tokenExtractor, TokenAuthenticationProvider tokenAuthenticationProvider) {
		this.authenticationEntryPoint = authenticationEntryPoint;
		this.successHandler = successHandler;
		this.failureHandler = failureHandler;
		this.loginAuthenticationProvider = loginAuthenticationProvider;
		this.httpSessionRequestCache = httpSessionRequestCache;
		this.tokenExtractor = tokenExtractor;
		this.tokenAuthenticationProvider = tokenAuthenticationProvider;
	}

	/**
	 * 登录过滤器
	 * 
	 * @throws Exception
	 */
	private LoginProcessingFilter buildLoginProcessingFilter() throws Exception {
		LoginProcessingFilter filter = new LoginProcessingFilter(FORM_BASED_LOGIN_ENTRY_POINT, successHandler,
				failureHandler, httpSessionRequestCache);
		filter.setAuthenticationManager(super.authenticationManager());
		return filter;
	}

	/**
	 * token验证过滤器
	 * 
	 * @return
	 * @throws Exception
	 */
	private TokenAuthenticationProcessFilter buildTokenAuthenticationProcessFilter() throws Exception {
		List<String> list = Lists.newArrayList(TOKEN_BASED_AUTH_ENTRY_POINT);
		SkipPathRequestMatcher matcher = new SkipPathRequestMatcher(list);
		TokenAuthenticationProcessFilter filter = new TokenAuthenticationProcessFilter(failureHandler, 
				tokenExtractor, matcher);
		filter.setAuthenticationManager(super.authenticationManager());
		return filter;
	}

	@Bean
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(loginAuthenticationProvider);
		auth.authenticationProvider(tokenAuthenticationProvider);
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable() // 因为使用的是JWT，因此这里可以关闭csrf了
				.exceptionHandling().authenticationEntryPoint(this.authenticationEntryPoint).and().sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS).and().authorizeRequests()
				.antMatchers(FORM_BASED_LOGIN_ENTRY_POINT).permitAll()
				.and().authorizeRequests().antMatchers(TOKEN_BASED_AUTH_ENTRY_POINT).authenticated()

				.and()
				.addFilterBefore(buildLoginProcessingFilter(), UsernamePasswordAuthenticationFilter.class) // 添加了过滤器需要在这配置
				.addFilterBefore(buildTokenAuthenticationProcessFilter(), UsernamePasswordAuthenticationFilter.class);
	}
}
