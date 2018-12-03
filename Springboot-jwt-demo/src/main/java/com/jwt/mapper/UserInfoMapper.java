package com.jwt.mapper;

import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Result;
import org.apache.ibatis.annotations.Results;
import org.apache.ibatis.annotations.Select;

import com.jwt.pojo.UserInfo;

public interface UserInfoMapper {

	@Select("SELECT * FROM SYC_USER WHERE U_USERNAME = #{username}")
	@Results({
		// property-本地字段名 column-数据库字段名
		@Result(property="uid",column="U_ID"),
		@Result(property="username",column="U_USERNAME"),
		@Result(property="password",column="U_PASSWORD")
	})
	public UserInfo findUserByName(@Param("username")String username);
}
