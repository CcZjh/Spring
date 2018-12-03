package com.jwt.security.auth.login;

import java.util.List;
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import com.alibaba.fastjson.JSON;
import com.jwt.pojo.UserInfo;
import com.jwt.pojo.UserRole;
import com.jwt.security.model.UserContext;
import com.jwt.service.UserInfoService;

/**
 * 类 Authentication 做完基本的处理后由此类 进行用户身份的认证
 * 此类是 AuthenticationManager 提供
 * 
 * @author 米斯特周
 *
 */
@Component
public class LoginAuthenticationProvider implements AuthenticationProvider {
	
	private Logger logger = LoggerFactory.getLogger(getClass());

	final UserInfoService userInfoService;
	
	@Autowired
	public LoginAuthenticationProvider(final UserInfoService userInfoService) {
		this.userInfoService = userInfoService;
	}
	
	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		Assert.notNull(authentication,"No authentication data provided");
		logger.debug("[Authentication info] - [{}]", JSON.toJSONString(authentication));
		
		String username = (String) authentication.getPrincipal();
		String password = (String) authentication.getCredentials();
		
		UserInfo uInfo = userInfoService.findUserByName(username);
		if (uInfo == null) {
			throw new UsernameNotFoundException("Username not found:"+username);
		}
		if (!StringUtils.equals(password, uInfo.getPassword())) {
			throw new BadCredentialsException("Authentication Failed. Username or Password not valid.");
		}
		// 调用根据用户查询角色的方法
		List<UserRole> roles = userInfoService.findRoleByUserName(uInfo);
		if (roles == null || roles.size() <= 0) {
			throw new InsufficientAuthenticationException("User has no roles assigned.");
		}
		List<GrantedAuthority> authorities = roles.stream()
				.map(authority -> new SimpleGrantedAuthority(authority.authority())).collect(Collectors.toList());

		UserContext userContext = UserContext.create(uInfo.getUsername(), authorities);
		
		return new UsernamePasswordAuthenticationToken(userContext, null, userContext.getAuthorities());
	}

	@Override
	public boolean supports(Class<?> authentication) {
		
		return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
	}

}
