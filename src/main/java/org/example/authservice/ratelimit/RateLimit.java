package org.example.authservice.ratelimit;

import java.lang.annotation.*;

@Target({ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface RateLimit {
    int requests();
    int durationSeconds();
}
