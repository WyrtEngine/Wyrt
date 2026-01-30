import express, { Express, Request, Response } from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import http from 'http';
import { ModuleContext } from '../module/ModuleContext';
import { AuthPayload } from './AuthManager';
import { HttpRateLimiter } from './HttpRateLimiter';
import colors from 'colors/safe';

export class HttpServer {
    private app: Express;
    private context: ModuleContext;
    private port: number;
    private server: http.Server | null = null;
    private rateLimiter: HttpRateLimiter;

    constructor(context: ModuleContext, port: number = 3001) {
        this.context = context;
        this.port = port;
        this.app = express();
        this.rateLimiter = new HttpRateLimiter();

        // Expose HTTP server globally for modules (e.g., wyrt_oauth)
        (globalThis as any).httpServer = this.app;

        this.setupMiddleware();
        this.setupRoutes();

        // Clean up rate limiter buckets periodically (every 5 minutes)
        setInterval(() => this.rateLimiter.cleanup(), 300000);
    }

    private setupMiddleware(): void {
        // Enable CORS for the frontend
        this.app.use(cors({
            origin: function(origin: string | undefined, callback: (err: Error | null, allow?: boolean) => void) {
                // Allow requests with no origin (like mobile apps or Postman)
                if (!origin) return callback(null, true);
                
                // Allow any localhost origin
                if (origin.startsWith('http://localhost:') || origin.startsWith('http://127.0.0.1:')) {
                    return callback(null, true);
                }
                
                // Block everything else
                callback(new Error('Not allowed by CORS'));
            },
            credentials: true,
            methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
            allowedHeaders: ['Content-Type', 'Authorization'],
            preflightContinue: false,
            optionsSuccessStatus: 200
        }));

        // Parse JSON bodies
        this.app.use(express.json());

        // Parse cookies
        this.app.use(cookieParser());

        // Request logging
        this.app.use((req, res, next) => {
            this.context.logger.debug(`HTTP ${req.method} ${req.path}`);
            next();
        });

        // Rate limiting - apply different limits based on route
        // Strict limit for auth endpoints (brute force protection)
        this.app.use('/api/auth', this.rateLimiter.middleware('auth'));
        // Normal limit for API endpoints
        this.app.use('/api', this.rateLimiter.middleware('api'));
        // Lenient limit for everything else
        this.app.use(this.rateLimiter.middleware('default'));
    }

    private setupRoutes(): void {
        // Health check
        this.app.get('/health', (req: Request, res: Response) => {
            res.json({
                status: 'ok',
                server: 'Wyrt',
                timestamp: Date.now()
            });
        });

        // Authentication routes
        this.app.post('/api/auth/register', async (req: Request, res: Response) => {
            try {
                const { username, password, email } = req.body;

                // Validate input
                if (!username || !password) {
                    return res.status(400).json({ 
                        success: false, 
                        message: 'Username and password are required' 
                    });
                }

                if (username.length < 3 || username.length > 20) {
                    return res.status(400).json({ 
                        success: false, 
                        message: 'Username must be between 3 and 20 characters' 
                    });
                }

                if (password.length < 6) {
                    return res.status(400).json({ 
                        success: false, 
                        message: 'Password must be at least 6 characters' 
                    });
                }

                // Check if username exists
                const existingUser = await this.context.prisma.account.findUnique({
                    where: { username }
                });

                if (existingUser) {
                    return res.status(409).json({
                        success: false,
                        message: 'Username already taken'
                    });
                }

                // Hash password
                const hashedPassword = await this.context.authManager.hashPassword(password);

                // Create account
                const newAccount = await this.context.prisma.account.create({
                    data: {
                        username,
                        email: email || `${username}@example.com`,
                        password_hash: hashedPassword
                    }
                });

                const userId = newAccount.id;

                // Generate token
                const payload: AuthPayload = {
                    userId: userId,
                    username: username,
                    gmlv: 0
                };

                const token = this.context.authManager.generateToken(payload);

                this.context.logger.info(colors.green(`New account registered via HTTP: ${username} (ID: ${userId})`));

                res.json({
                    success: true,
                    token: token,
                    id: userId,
                    username: username,
                    message: 'Account created successfully'
                });

            } catch (error) {
                this.context.logger.error('Registration error:', error);
                res.status(500).json({ 
                    success: false, 
                    message: 'Registration failed. Please try again.' 
                });
            }
        });

        this.app.post('/api/auth/login', async (req: Request, res: Response) => {
            try {
                const { username, password } = req.body;

                // Validate input
                if (!username || !password) {
                    return res.status(400).json({ 
                        success: false, 
                        message: 'Username and password are required' 
                    });
                }

                // Find account by username
                const account = await this.context.prisma.account.findUnique({
                    where: { username }
                });

                if (!account) {
                    return res.status(401).json({
                        success: false,
                        message: 'Invalid username or password'
                    });
                }

                // Verify password
                const passwordValid = await this.context.authManager.comparePassword(password, account.password_hash);

                if (!passwordValid) {
                    return res.status(401).json({
                        success: false,
                        message: 'Invalid username or password'
                    });
                }

                // Update last login (fire and forget)
                this.context.prisma.account.update({
                    where: { id: account.id },
                    data: { last_login: new Date() }
                }).catch(err => console.error("Failed to update last_login:", err));

                // Generate token
                const payload: AuthPayload = {
                    userId: account.id,
                    username: account.username,
                    gmlv: 0
                };

                const token = this.context.authManager.generateToken(payload);

                this.context.logger.info(colors.green(`User logged in via HTTP: ${username} (ID: ${account.id})`));

                res.json({
                    success: true,
                    token: token,
                    id: account.id,
                    username: account.username,
                    message: 'Login successful'
                });

            } catch (error) {
                this.context.logger.error('Login error:', error);
                res.status(500).json({ 
                    success: false, 
                    message: 'Login failed. Please try again.' 
                });
            }
        });

        // Verify token endpoint
        // Delegates to OAuth module if present (for OAuth tokens),
        // otherwise uses engine's authManager (for username/password tokens)
        this.app.get('/api/auth/verify', (req: Request, res: Response) => {
            const authHeader = req.headers.authorization;

            if (!authHeader || !authHeader.startsWith('Bearer ')) {
                return res.status(401).json({
                    success: false,
                    message: 'No token provided'
                });
            }

            const token = authHeader.substring(7);

            // Try OAuth module first (if configured)
            const oauthModule = this.context.getModule('wyrt_oauth') as any;
            if (oauthModule && typeof oauthModule.getOAuthManager === 'function') {
                const oauthManager = oauthModule.getOAuthManager();
                if (oauthManager && typeof oauthManager.verifySessionToken === 'function') {
                    try {
                        const session = oauthManager.verifySessionToken(token);
                        if (session) {
                            return res.json({
                                success: true,
                                userId: session.accountId,
                                username: session.username,
                                displayName: session.displayName,
                                gameId: session.gameId || null
                            });
                        }
                    } catch (e) {
                        // OAuth verification failed, try engine auth below
                    }
                }
            }

            // Fallback to engine's authManager (for username/password tokens)
            const payload = this.context.authManager.verifyToken(token);

            if (!payload) {
                return res.status(401).json({
                    success: false,
                    message: 'Invalid or expired token'
                });
            }

            res.json({
                success: true,
                userId: payload.userId,
                username: payload.username,
                gmlv: payload.gmlv
            });
        });

        // Game config API - returns game-specific configuration for clients
        this.app.get('/api/games/:gameId/config', (req: Request, res: Response) => {
            const { gameId } = req.params;

            // Get the game module
            const module = this.context.getModule(gameId);
            if (!module) {
                return res.status(404).json({
                    success: false,
                    message: `Game '${gameId}' not found`
                });
            }

            // Return game config with sensible defaults
            const config = module.gameConfig || {};
            res.json({
                success: true,
                gameId,
                config: {
                    commandPrefix: config.commandPrefix ?? null,  // null = MUD-style (no prefix)
                    echoCommands: config.echoCommands ?? true,
                }
            });
        });

        // Generic module data API
        this.app.get('/api/data/:module/:category/:name?', async (req: Request, res: Response) => {
            try {
                const { module: moduleName, category, name } = req.params;

                // Check if module exists
                const module = this.context.getModule(moduleName);
                if (!module) {
                    return res.status(404).json({
                        success: false,
                        message: `Module '${moduleName}' not found`
                    });
                }

                // Build data path
                const dataPath = name
                    ? `${moduleName}.${category}.${name}`
                    : `${moduleName}.${category}`;

                const data = this.context.data[moduleName]?.[category];

                if (!data) {
                    return res.status(404).json({
                        success: false,
                        message: `Data category '${category}' not found in module '${moduleName}'`
                    });
                }

                // If specific item requested
                if (name) {
                    const item = data[name];
                    if (!item) {
                        return res.status(404).json({
                            success: false,
                            message: `Item '${name}' not found in ${moduleName}.${category}`
                        });
                    }

                    return res.json({
                        success: true,
                        data: item
                    });
                }

                // Return entire category
                res.json({
                    success: true,
                    data: data
                });

            } catch (error) {
                this.context.logger.error(`Error loading module data: ${error}`);
                res.status(500).json({
                    success: false,
                    message: 'Internal server error'
                });
            }
        });

        // Note: 404 handler is registered separately via registerFallbackRoutes()
        // after all modules have had a chance to register their routes
    }

    /**
     * Register fallback routes (404 handler)
     * Should be called AFTER all modules have registered their routes
     */
    public registerFallbackRoutes(): void {
        this.app.use((req: Request, res: Response) => {
            res.status(404).json({
                success: false,
                message: 'Endpoint not found'
            });
        });
    }

    public start(): void {
        this.server = this.app.listen(this.port, () => {
            this.context.logger.info(colors.cyan(`HTTP Server listening on port ${this.port}`));
        });
    }

    public stop(): Promise<void> {
        return new Promise((resolve) => {
            if (this.server) {
                this.server.close(() => {
                    this.context.logger.info(colors.yellow(`HTTP Server stopped`));
                    this.server = null;
                    resolve();
                });
            } else {
                resolve();
            }
        });
    }
}