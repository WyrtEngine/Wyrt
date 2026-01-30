//----------------------------------
// Wyrt - An MMO Engine
//----------------------------------
// Copyright (c) 2025 LoxleyXI
//
// https://github.com/LoxleyXI/Wyrt
//----------------------------------
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/
//----------------------------------
import { Request, Response, NextFunction, RequestHandler } from 'express';
import { LeakyBucket } from './LeakyBucket';

interface RateLimitConfig {
    capacity: number;
    refillRate: number;
}

/**
 * HTTP Rate Limiter using Leaky Bucket algorithm
 * Provides IP-based rate limiting for Express routes
 */
export class HttpRateLimiter {
    private buckets: Map<string, LeakyBucket> = new Map();

    // Different limits for different endpoint types
    private readonly limits: Record<string, RateLimitConfig> = {
        auth: { capacity: 10, refillRate: 1 },      // Strict: 10 attempts, 1/sec refill
        api: { capacity: 60, refillRate: 10 },      // Normal: 60 requests, 10/sec refill
        default: { capacity: 100, refillRate: 20 }  // Lenient: 100 requests, 20/sec refill
    };

    /**
     * Get client IP address from request
     * Handles proxied requests (X-Forwarded-For) and direct connections
     */
    private getClientIp(req: Request): string {
        // Check for forwarded IP (behind proxy/load balancer)
        const forwarded = req.headers['x-forwarded-for'];
        if (forwarded) {
            // X-Forwarded-For can contain multiple IPs, take the first (client)
            const ips = Array.isArray(forwarded) ? forwarded[0] : forwarded;
            return ips.split(',')[0].trim();
        }

        // Fall back to direct connection IP
        return req.ip || req.socket.remoteAddress || 'unknown';
    }

    /**
     * Get or create a bucket for the given key and limit type
     */
    private getBucket(key: string, type: string): LeakyBucket {
        const bucketKey = `${type}:${key}`;

        if (!this.buckets.has(bucketKey)) {
            const config = this.limits[type] || this.limits.default;
            this.buckets.set(bucketKey, new LeakyBucket(config.capacity, config.refillRate));
        }

        return this.buckets.get(bucketKey)!;
    }

    /**
     * Create rate limiting middleware for a specific endpoint type
     * @param type - 'auth' (strict), 'api' (normal), or 'default' (lenient)
     */
    public middleware(type: 'auth' | 'api' | 'default' = 'default'): RequestHandler {
        return (req: Request, res: Response, next: NextFunction): void => {
            const clientIp = this.getClientIp(req);
            const bucket = this.getBucket(clientIp, type);

            if (bucket.consume(1)) {
                // Request allowed
                next();
            } else {
                // Rate limit exceeded
                const config = this.limits[type] || this.limits.default;
                res.status(429).json({
                    success: false,
                    error: 'Too many requests',
                    message: 'Please slow down and try again later',
                    retryAfter: Math.ceil(1 / config.refillRate)
                });
            }
        };
    }

    /**
     * Clean up buckets that have fully refilled (inactive clients)
     * Should be called periodically to prevent memory leaks
     */
    public cleanup(): void {
        for (const [key, bucket] of this.buckets.entries()) {
            // Extract limit type from key (format: "type:ip")
            const type = key.split(':')[0];
            const config = this.limits[type] || this.limits.default;

            // Remove bucket if fully refilled (client has been idle)
            if (bucket.getTokens() >= config.capacity) {
                this.buckets.delete(key);
            }
        }
    }

    /**
     * Get current bucket count (for monitoring)
     */
    public getBucketCount(): number {
        return this.buckets.size;
    }
}
