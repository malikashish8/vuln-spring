package com.example.vulnspring;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
@WebFilter(urlPatterns={"*"})
public class SessionFilter implements Filter {
	private static final Logger logger = LoggerFactory.getLogger(SessionFilter.class);

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest req = (HttpServletRequest) request;
		HttpServletResponse res = (HttpServletResponse) response;
		String username = (String) req.getSession().getAttribute("username");
		
		logger.debug(req.getMethod() + " " + req.getServletPath() + " requested");
		if (username == null && req.getServletPath().matches("^\\/login$")) {
			chain.doFilter(req, res);
		} else if(username != null) {
			chain.doFilter(req, res);
		}
		else {
			res.sendRedirect("/login");
		}

	}
}