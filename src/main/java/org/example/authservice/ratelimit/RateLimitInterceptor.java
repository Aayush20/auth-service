package org.example.authservice.ratelimit;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Refill;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class RateLimitInterceptor implements HandlerInterceptor {

    private final Map<String, Bucket> bucketMap = new ConcurrentHashMap<>();

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws Exception {

        if (handler instanceof HandlerMethod method) {
            RateLimit rateLimit = method.getMethodAnnotation(RateLimit.class);

            if (rateLimit != null) {
                String key = request.getRemoteAddr() + ":" + method.getMethod().getName();
                Bucket bucket = bucketMap.computeIfAbsent(key, k ->
                        Bucket.builder()
                                .addLimit(Bandwidth.classic(
                                        rateLimit.requests(),
                                        Refill.intervally(rateLimit.requests(), Duration.ofSeconds(rateLimit.durationSeconds()))
                                )).build()
                );

                if (!bucket.tryConsume(1)) {
                    response.setStatus(429);
                    response.getWriter().write("Rate limit exceeded. Please try again later.");
                    return false;
                }
            }
        }

        return true;
    }
}
