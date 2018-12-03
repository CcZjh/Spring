package com.jwt.controller;

import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.ObjectUtils.Null;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.jwt.utils.RequestStreamUtil;

@RestController
public class UserController {

	@RequestMapping("/api/login")
	public Object login(HttpServletRequest request, HttpServletResponse response) {
		Object object = request.getAttribute("tokenMap");
		System.out.println("111111111111111"+object);
		return object;
	}
	
	@GetMapping("/api/test1")
    public String test1() {
        return "test1";
    }

    @RequestMapping("/test2")
    public String test2(HttpServletRequest request) {
//    	String str2 = request.getParameter("test");
    	String str1 = RequestStreamUtil.toString(request);
    	System.out.println(str1);
        return str1;
    }
}
