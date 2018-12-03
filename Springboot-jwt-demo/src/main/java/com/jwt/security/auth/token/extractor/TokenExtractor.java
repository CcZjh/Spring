package com.jwt.security.auth.token.extractor;

import org.springframework.stereotype.Component;

/**
 * 实现这个接口应该返回原Base-64编码
 * 表示Token
 */
public interface TokenExtractor {
	
    String extract(String payload);
}