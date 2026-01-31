/**
 * @module wyrt_oauth
 * @description OAuth authentication module supporting Discord, Google, Steam, and other providers
 * @category Auth
 *
 * @features
 * - Discord OAuth2 integration
 * - Google OAuth2 integration (planned)
 * - Steam OpenID integration (planned)
 * - Automatic account linking
 * - JWT token generation
 * - Game module provides OAuth credentials (not engine-level)
 * - HTTP route registration (/oauth/:provider)
 * - Callback handling and token exchange
 *
 * @usage
 * ```typescript
 * // Game modules configure OAuth by calling configureOAuth():
 * const oauthModule = context.getModule('wyrt_oauth');
 * oauthModule.configureOAuth({
 *     jwtSecret: process.env.OAUTH_JWT_SECRET,
 *     discord: {
 *         clientId: process.env.DISCORD_CLIENT_ID,
 *         clientSecret: process.env.DISCORD_CLIENT_SECRET,
 *         callbackUrl: process.env.DISCORD_CALLBACK_URL
 *     }
 * });
 *
 * // OAuth routes are auto-registered:
 * // GET /oauth/discord - Redirects to Discord login
 * // GET /oauth/discord/callback - Handles callback
 *
 * // Access OAuth manager for custom integration
 * const oauthManager = oauthModule.getOAuthManager();
 * ```
 *
 * @exports OAuthManager - Manages OAuth providers and authentication
 * @exports DiscordProvider - Discord OAuth2 provider implementation
 */
//----------------------------------
// Wyrt OAuth Module
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

import { IModule } from '../../../src/module/IModule.js';
import { ModuleContext } from '../../../src/module/ModuleContext.js';
import { OAuthManager } from './OAuthManager.js';
import { DiscordProvider } from './providers/DiscordProvider.js';
import { createOAuthRouter, createSessionRouter } from './routes/oauth.js';
import type { Express } from 'express';

interface OAuthConfig {
    jwtSecret: string;
    providers: {
        discord?: {
            enabled: boolean;
            clientId: string;
            clientSecret: string;
            callbackUrl: string;
        };
        // Future providers: google, steam, etc.
    };
}

/**
 * OAuth configuration provided by game modules
 */
export interface GameOAuthConfig {
    jwtSecret?: string;
    discord?: {
        clientId: string;
        clientSecret: string;
        callbackUrl: string;
    };
    // Future providers: google, steam, etc.
}

export default class WyrtOAuthModule implements IModule {
    name = 'wyrt_oauth';
    version = '1.0.0';
    description = 'OAuth authentication module - supports Discord, Google, Steam, and other providers';
    dependencies = ['wyrt_data']; // Requires wyrt_data for database access

    private context!: ModuleContext;
    private oauthManager!: OAuthManager;
    private config!: OAuthConfig;
    private configured: boolean = false;
    private customPrismaSet: boolean = false;

    async initialize(context: ModuleContext): Promise<void> {
        this.context = context;

        // Initialize with default config (no providers enabled)
        // Game modules will call configureOAuth() to set up their credentials
        this.config = {
            jwtSecret: process.env.OAUTH_JWT_SECRET || 'wyrt-oauth-secret-change-in-production',
            providers: {}
        };

        // Create OAuth manager
        this.oauthManager = new OAuthManager(this.config.jwtSecret);

        console.log(`[${this.name}] Initialized - waiting for game module to configure OAuth`);
    }

    /**
     * Configure OAuth credentials from a game module.
     * Game modules should call this during their initialize() phase.
     */
    configureOAuth(config: GameOAuthConfig): void {
        if (config.jwtSecret) {
            this.config.jwtSecret = config.jwtSecret;
            // Update OAuth manager with new secret
            this.oauthManager = new OAuthManager(this.config.jwtSecret);
        }

        // Configure Discord provider
        if (config.discord?.clientId && config.discord?.clientSecret) {
            this.config.providers.discord = {
                enabled: true,
                clientId: config.discord.clientId,
                clientSecret: config.discord.clientSecret,
                callbackUrl: config.discord.callbackUrl || 'http://localhost:4040/oauth/discord/callback'
            };

            // Register the provider
            const discordProvider = new DiscordProvider({
                clientId: this.config.providers.discord.clientId,
                clientSecret: this.config.providers.discord.clientSecret,
                callbackUrl: this.config.providers.discord.callbackUrl,
            });
            this.oauthManager.registerProvider(discordProvider);
            console.log(`[${this.name}] Discord OAuth configured`);
        }

        this.configured = true;
        console.log(`[${this.name}] OAuth configured by game module`);
    }

    /**
     * Check if OAuth has been configured by a game module
     */
    isConfigured(): boolean {
        return this.configured;
    }

    /**
     * Set a custom Prisma client (for game modules with their own database)
     * Call this before activate() to prevent wyrt_data from overwriting it.
     */
    setPrisma(prisma: any): void {
        this.oauthManager.setPrisma(prisma);
        this.customPrismaSet = true;
    }

    async activate(): Promise<void> {
        // Only use wyrt_data's Prisma if no custom Prisma was set by a game module
        if (!this.customPrismaSet) {
            const wyrtData = this.context.getModule('wyrt_data') as any;
            if (wyrtData && typeof wyrtData.getDatabase === 'function') {
                const prisma = wyrtData.getDatabase();
                this.oauthManager.setPrisma(prisma);
            } else {
                console.warn('[wyrt_oauth] wyrt_data module not available - OAuth account creation will fail');
            }
        }

        // Register HTTP routes
        this.registerRoutes();

        console.log(`[${this.name}] Activated - OAuth providers ready`);
    }

    async deactivate(): Promise<void> {
        // Cleanup if needed
        console.log(`[${this.name}] Deactivated`);
    }

    /**
     * Register HTTP routes with Wyrt's HTTP server
     */
    private registerRoutes(): void {
        // Get HTTP server from context
        const httpServer = (globalThis as any).httpServer as Express;
        if (!httpServer) {
            console.warn('[wyrt_oauth] HTTP server not available - routes not registered');
            return;
        }

        // Create and register OAuth router
        const oauthRouter = createOAuthRouter(this.oauthManager);
        httpServer.use('/oauth', oauthRouter);

        // Create and register session router (for /api/session, /api/logout)
        const sessionRouter = createSessionRouter(this.oauthManager);
        httpServer.use('/api', sessionRouter);

        console.log('[wyrt_oauth] Registered OAuth routes: /oauth/:provider, /oauth/:provider/callback');
        console.log('[wyrt_oauth] Registered session routes: /api/session, /api/logout');
    }

    /**
     * Get the OAuth manager (for WebSocket auth integration)
     */
    getOAuthManager(): OAuthManager {
        return this.oauthManager;
    }
}
