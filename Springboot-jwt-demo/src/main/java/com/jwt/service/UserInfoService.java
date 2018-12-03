package com.jwt.service;

import java.util.List;

import com.jwt.pojo.UserInfo;
import com.jwt.pojo.UserRole;

public interface UserInfoService {

	UserInfo findUserByName(String username);
	
	List<UserRole> findRoleByUserName(UserInfo uInfo);
}
