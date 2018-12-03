package com.jwt.service.Impl;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.google.common.collect.Lists;
import com.jwt.mapper.UserInfoMapper;
import com.jwt.pojo.UserInfo;
import com.jwt.pojo.UserRole;
import com.jwt.service.UserInfoService;

@Service
public class UserInfoServiceImpl implements UserInfoService {

	@Autowired
	private UserInfoMapper userInfoMapper;
	
	@Override
	public UserInfo findUserByName(String username) {
		
		return userInfoMapper.findUserByName(username);
	}

	@Override
	public List<UserRole> findRoleByUserName(UserInfo uInfo) {
		if ("周大帅".equals(uInfo.getUsername())) {
			 return Lists.newArrayList(new UserRole("ROLE_ADMIN"));
		}
		return null;
	}

}
