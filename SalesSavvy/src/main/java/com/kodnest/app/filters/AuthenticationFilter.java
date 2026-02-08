package com.kodnest.app.filters;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.annotation.WebFilter;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.Arrays;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import com.kodnest.app.entities.Role;
import com.kodnest.app.entities.User;
import com.kodnest.app.userrepositories.UserRepository;
import com.kodnest.app.userservices.AuthServiceContract;

@WebFilter(urlPatterns = {"/api/*", "/admin/*"})
@Component
public class AuthenticationFilter implements Filter {

    private static final Logger logger = LoggerFactory.getLogger(AuthenticationFilter.class);

    private final AuthServiceContract authService;
    private final UserRepository userRepository;

    // CHANGE THIS WHEN DEPLOYED
    private static final String ALLOWED_ORIGIN = "https://ecommerce-salessavvy.onrender.com";

    private static final String[] UNAUTHENTICATED_PATHS = {
            "/api/users/register",
            "/api/auth/login"
    };

    public AuthenticationFilter(AuthServiceContract authService, UserRepository userRepository) {
        this.authService = authService;
        this.userRepository = userRepository;
        System.out.println("AuthenticationFilter started");
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        try {
            String requestURI = httpRequest.getRequestURI();
            logger.info("Request URI: {}", requestURI);

            // ===== 1. ALLOW FRONTEND AND STATIC RESOURCES =====
            if (requestURI.equals("/") ||
                requestURI.equals("/index.html") ||
                requestURI.startsWith("/assets/") ||
                requestURI.startsWith("/static/") ||
                requestURI.startsWith("/favicon.ico") ||
                requestURI.startsWith("/manifest.json") ||
                requestURI.startsWith("/logo.png") ||
                requestURI.startsWith("/vite.svg")) {

                chain.doFilter(request, response);
                return;
            }

            // ===== 2. ALLOW PUBLIC PRODUCT APIS WITHOUT LOGIN =====
            if (requestURI.startsWith("/api/products")) {
                chain.doFilter(request, response);
                return;
            }

            // ===== 3. CORS PREFLIGHT =====
            if ("OPTIONS".equalsIgnoreCase(httpRequest.getMethod())) {
                setCORSHeaders(httpResponse);
                return;
            }

            // ===== 4. ALLOW LOGIN & REGISTER APIS =====
            if (Arrays.asList(UNAUTHENTICATED_PATHS).contains(requestURI)) {
                chain.doFilter(request, response);
                return;
            }

            // ===== 5. TOKEN VALIDATION FOR PROTECTED APIS =====
            String token = extractToken(httpRequest);
            System.out.println("TOKEN = " + token);

            if (token == null || !authService.validateToken(token)) {
                sendErrorResponse(httpResponse, HttpServletResponse.SC_UNAUTHORIZED,
                        "Unauthorized: Invalid or missing token");
                return;
            }

            // ===== 6. VALIDATE USER FROM TOKEN =====
            String username = authService.extractUsername(token);
            Optional<User> userOptional = userRepository.findByUsername(username);

            if (userOptional.isEmpty()) {
                sendErrorResponse(httpResponse, HttpServletResponse.SC_UNAUTHORIZED,
                        "Unauthorized: User not found");
                return;
            }

            User authenticatedUser = userOptional.get();
            Role role = authenticatedUser.getRole();

            logger.info("Authenticated User: {}, Role: {}", authenticatedUser.getUsername(), role);

            // ===== 7. ROLE BASED SECURITY =====
            if (requestURI.startsWith("/admin/") && role != Role.ADMIN) {
                sendErrorResponse(httpResponse, HttpServletResponse.SC_FORBIDDEN,
                        "Forbidden: Admin access required");
                return;
            }

            if (requestURI.startsWith("/api/") && role != Role.CUSTOMER) {
                sendErrorResponse(httpResponse, HttpServletResponse.SC_FORBIDDEN,
                        "Forbidden: Customer access required");
                return;
            }

            // Attach authenticated user
            httpRequest.setAttribute("authenticatedUser", authenticatedUser);

            chain.doFilter(request, response);

        } catch (Exception e) {
            logger.error("Error in AuthenticationFilter", e);
            sendErrorResponse(httpResponse, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "Internal server error");
        }
    }

    private String extractToken(HttpServletRequest request) {

        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }

        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("authToken".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }

        return null;
    }

    private void setCORSHeaders(HttpServletResponse response) {
        response.setHeader("Access-Control-Allow-Origin", ALLOWED_ORIGIN);
        response.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        response.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
        response.setHeader("Access-Control-Allow-Credentials", "true");
        response.setStatus(HttpServletResponse.SC_OK);
    }

    private void sendErrorResponse(HttpServletResponse response, int statusCode, String message)
            throws IOException {
        response.setStatus(statusCode);
        response.getWriter().write(message);
    }
}
