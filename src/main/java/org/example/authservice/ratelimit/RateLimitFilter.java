//package org.example.authservice.ratelimit;
//
//import io.github.bucket4j.Bandwidth;
//import io.github.bucket4j.Bucket;
//import io.github.bucket4j.Refill;
//import jakarta.servlet.FilterChain;
//import jakarta.servlet.ServletException;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import org.springframework.stereotype.Component;
//import org.springframework.web.filter.OncePerRequestFilter;
//
//import java.io.IOException;
//import java.time.Duration;
//import java.util.Map;
//import java.util.concurrent.ConcurrentHashMap;
//
//@Component
//public class RateLimitFilter extends OncePerRequestFilter {
//
//    private final Map<String, Bucket> bucketCache = new ConcurrentHashMap<>();
//
//    @Override
//    protected void doFilterInternal(HttpServletRequest request,
//                                    HttpServletResponse response,
//                                    FilterChain filterChain) throws ServletException, IOException {
//
//        String ip = request.getRemoteAddr(); // You can use JWT user ID for per-user limits
//        Bucket bucket = bucketCache.computeIfAbsent(ip, this::newBucket);
//
//        if (bucket.tryConsume(1)) {
//            filterChain.doFilter(request, response);
//        } else {
//            response.setStatus(429);
//            response.getWriter().write("Rate limit exceeded. Try again later.");
//        }
//    }
//
//    private Bucket newBucket(String key) {
//        return Bucket.builder()
//                .addLimit(Bandwidth.classic(10, Refill.greedy(10, Duration.ofMinutes(1))))
//                .build();
//    }
//}
