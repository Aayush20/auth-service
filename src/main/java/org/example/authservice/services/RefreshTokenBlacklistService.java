package org.example.authservice.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Service
public class RefreshTokenBlacklistService {

    private static final String PREFIX = "blacklist:refresh:";

    @Autowired
    private StringRedisTemplate redisTemplate;

    public void blacklist(String token, Duration ttl) {
        redisTemplate.opsForValue().set(PREFIX + token, "revoked", ttl);
    }

    public boolean isBlacklisted(String token) {
        return Boolean.TRUE.equals(redisTemplate.hasKey(PREFIX + token));
    }
}
