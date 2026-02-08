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

@WebFilter(urlPatterns = {"/api/*", "/admin/*", "/*"})
@Component
public class AuthenticationFilter implements Filter {

    private static final Logger logger = LoggerFactory.getLogger(AuthenticationFilter.class);

    private final AuthServiceContract authService;
    private final UserRepository userRepository;

    private static final String ALLOWED_ORIGIN = "http://localhost:9090";

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

        String requestURI = httpRequest.getRequestURI();
        logger.info("Request URI: {}", requestURI);

        // ===== Allow React Static Files =====
        if (isPublicResource(requestURI)) {
            chain.doFilter(request, response);
            return;
        }

        // ===== Handle CORS Preflight =====
        if ("OPTIONS".equalsIgnoreCase(httpRequest.getMethod())) {
            setCORSHeaders(httpResponse);
            chain.doFilter(request, response);
            return;
        }

        // ===== Allow Login & Register Without Token =====
        if (Arrays.asList(UNAUTHENTICATED_PATHS).contains(requestURI)) {
            chain.doFilter(request, response);
            return;
        }

        try {
            String token = extractToken(httpRequest);
            logger.info("TOKEN = {}", token);

            if (token == null || !authService.validateToken(token)) {
                sendErrorResponse(httpResponse, HttpServletResponse.SC_UNAUTHORIZED,
                        "Unauthorized: Invalid or missing token");
                return;
            }

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

            if (requestURI.startsWith("/admin/") && role != Role.ADMIN) {
                sendErrorResponse(httpResponse, HttpServletResponse.SC_FORBIDDEN,
                        "Forbidden: Admin access required");
                return;
            }

            httpRequest.setAttribute("authenticatedUser", authenticatedUser);

            chain.doFilter(request, response);

        } catch (Exception e) {
            logger.error("Error in AuthenticationFilter", e);
            sendErrorResponse(httpResponse, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "Internal server error");
        }
    }

    // ===== Allow Frontend Files Without Authentication =====
    private boolean isPublicResource(String uri) {
        return uri.equals("/")
                || uri.startsWith("/index.html")
                || uri.startsWith("/static/")
                || uri.startsWith("/assets/")
                || uri.endsWith(".js")
                || uri.endsWith(".css")
                || uri.endsWith(".html")
                || uri.endsWith(".png")
                || uri.endsWith(".jpg")
                || uri.endsWith(".jpeg")
                || uri.endsWith(".gif")
                || uri.endsWith(".svg")
                || uri.endsWith(".ico")
                || uri.endsWith(".woff")
                || uri.endsWith(".woff2")
                || uri.endsWith(".ttf");
    }

    // ===== Extract JWT Token =====
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

    // ===== CORS Headers =====
    private void setCORSHeaders(HttpServletResponse response) {
        response.setHeader("Access-Control-Allow-Origin", ALLOWED_ORIGIN);
        response.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        response.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
        response.setHeader("Access-Control-Allow-Credentials", "true");
    }

    // ===== Error Response =====
    private void sendErrorResponse(HttpServletResponse response, int statusCode, String message)
            throws IOException {
        response.setStatus(statusCode);
        response.getWriter().write(message);
    }
}
