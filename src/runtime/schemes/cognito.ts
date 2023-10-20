import type {
    EndpointsOption,
    SchemePartialOptions,
    TokenableSchemeOptions,
    UserOptions,
    HTTPRequest,
    RefreshableSchemeOptions,
} from "../../types";
import {Auth as CognitoAuth} from "@aws-amplify/auth";
import {Auth, ExpiredAuthSessionError, RequestHandler} from "..";
import {BaseScheme} from './base';
import {type Scheme, type SchemeCheck, type SchemeOptions} from "../../types";
import {Amplify} from "@aws-amplify/core";
import {CognitoUserSession} from "amazon-cognito-identity-js";
import {getProp} from "../../utils";
import {CognitoToken} from "./cognito/token";
import {CognitoRefreshToken} from "./cognito/refresh-token";
import {CognitoStorage} from "./cognito/storage";

export interface CognitoSchemeEndpoints extends EndpointsOption {
    login: HTTPRequest;
    logout: HTTPRequest | false;
    user: HTTPRequest | false;
}

export interface CognitoCredentials {
    userPoolId: string;
    userPoolWebClientId: string;
    region: string;
}

export interface CognitoSchemeOptions
    extends SchemeOptions,
        TokenableSchemeOptions,
        RefreshableSchemeOptions {
    endpoints: CognitoSchemeEndpoints;
    user: UserOptions;
    grantType: string | false;
    scope: string[] | false;
    credentials: CognitoCredentials;
    autoLogout: boolean;
}

const DEFAULTS: SchemePartialOptions<CognitoSchemeOptions> = {
    name: "cognito",
    autoLogout: false,
    token: {
        property: "access_token",
        type: "Bearer",
        name: "Authorization",
        maxAge: 1800,
        global: true,
        expirationPrefix: "_token_expiration.",
    },
    refreshToken: {
        property: "refresh_token",
        maxAge: 60 * 60 * 24 * 30,
        expirationPrefix: "_refresh_token_expiration.",
    },
    user: {
        property: "data",
        autoFetch: true,
    },
    credentials: {},
};

export class CognitoAuthScheme<
    OptionsT extends CognitoSchemeOptions = CognitoSchemeOptions
> extends BaseScheme<OptionsT> implements Scheme<OptionsT>{
    token: CognitoToken | null;
    refreshToken: CognitoRefreshToken | null;
    requestHandler: RequestHandler;

    constructor(
        $auth: Auth,
        options: SchemePartialOptions<CognitoSchemeOptions>,
        ...defaults: SchemePartialOptions<CognitoSchemeOptions>[]
    ) {
        super($auth, options as OptionsT, ...(defaults as OptionsT[]), DEFAULTS as OptionsT);

        Amplify.configure({
            Auth: {
                ...this.options.credentials,
                storage: new CognitoStorage(
                    this.$auth.$storage,
                    this.options.credentials.userPoolWebClientId
                ),
            },
        });

        this.token = null;
        this.refreshToken = null;
        this.requestHandler = new RequestHandler(this, this.$auth.ctx.$http);
    }

    check(checkStatus = false): SchemeCheck {
        const response = {
            valid: false,
            tokenExpired: false,
            refreshTokenExpired: false,
            isRefreshable: true,
        };

        // Sync tokens
        const token = this.token?.sync();
        this.refreshToken?.sync();

        // Token is required but not available
        if (!token) {
            return response;
        }

        // Check status wasn't enabled, let it pass
        if (!checkStatus) {
            response.valid = true;
            return response;
        }

        // Get status
        const tokenStatus = this.token?.status();
        const refreshTokenStatus = this.refreshToken?.status();

        // Tokens status is unknown. Force reset
        if (refreshTokenStatus?.unknown() || tokenStatus?.unknown()) {
            return response;
        }

        // Refresh token has expired. There is no way to refresh. Force reset.
        if (refreshTokenStatus?.expired()) {
            response.refreshTokenExpired = true;
            return response;
        }

        // Token has expired, Force reset.
        if (tokenStatus?.expired()) {
            response.tokenExpired = true;
            return response;
        }

        response.valid = true;

        return response;
    }

    async mounted() {
        let session;

        try {
            // Get Cognito Session
            session = await this._getCognitoSession();
        } catch (e) {
            // error handler placeholder
        }

        // Reset auth if no session
        if (!session) {
            this.$auth.reset();
            return;
        }

        this._initTokens(session);

        const {tokenExpired, refreshTokenExpired} = this.check(true);

        // Force reset if refresh token has expired
        // Or if `autoLogout` is enabled and token has expired
        if (refreshTokenExpired || (tokenExpired && this.options.autoLogout)) {
            this.$auth.reset();
        }

        return this.$auth.fetchUserOnce();
    }

    async login({data}) {
        // logout and reset auth
        await this.logout();

        // Sign in AWS Cognito service
        const user = await CognitoAuth.signIn(data.username, data.password);
        const session = user.getSignInUserSession();

        // Set tokens
        this._initTokens(session);

        // Initialize request interceptor if not initialized
        if (!this.requestHandler.interceptor) {
            this.initializeRequestInterceptor();
        }

        // Fetch user if `autoFetch` is enabled
        if (this.options.user.autoFetch) {
            await this.fetchUser();
        }

        return session;
    }

    _initTokens(session: CognitoUserSession) {
        if (!this.token) {
            this.token = new CognitoToken(session, {
                name: this.name,
                token: this.options.token!,
                requestHandler: this.requestHandler
            }, this.$auth.$storage);
        }

        if (!this.refreshToken) {
            this.refreshToken = new CognitoRefreshToken(session, {
                name: this.name,
                refreshToken: this.options.refreshToken!
            }, this.$auth.$storage);
        }
    }

    _updateTokens(session: CognitoUserSession) {
        if (!session) {
            throw new Error("Session error");
        }

        this.token = new CognitoToken(session, {
            name: this.name, token: this.options.token!,
            requestHandler: this.requestHandler
        }, this.$auth.$storage);

        this.refreshToken = new CognitoRefreshToken(session, {
            name: this.name,
            refreshToken: this.options.refreshToken!
        }, this.$auth.$storage);
    }

    async refreshTokens() {
        // Get refresh token
        const refreshToken = this.refreshToken?.get();

        // Refresh token is required but not available
        if (!refreshToken) {
            return;
        }

        // Get refresh token status
        const refreshTokenStatus = this.refreshToken?.status();

        // Refresh token is expired. There is no way to refresh. Force reset.
        if (refreshTokenStatus?.expired()) {
            this.$auth.reset();
            throw new ExpiredAuthSessionError();
        }

        // Refresh AWS session
        await this._refreshSession();

        // Get current user session
        const session = await this._getCognitoSession();

        // update tokens
        this._updateTokens(session);

        return session;
    }

    async fetchUser() {
        // Token is required but not available
        if (!this.check().valid) {
            return;
        }

        let cognitoUser = null;

        // Try to get the current pool user
        try {
            cognitoUser = await this._getCognitoUser();
        } catch (e) {
            // error handler placeholder
        }

        // Skip if no cognito user is logged in
        if (cognitoUser === null) {
            return;
        }

        let user: any = {};

        // cognito user info
        user.cognito = {
            username: cognitoUser.username,
        };

        // User endpoint is disabled
        if (!this.options.endpoints.user) {
            this.$auth.setUser(user);
            return;
        }

        // Try to fetch user and then set
        return this.$auth
            .requestWith({
                url: this.options.endpoints.user
            })
            .then((response) => {
                const userData = getProp(response, this.options.user.property!);
                if (!userData) {
                    const error = new Error(`User Data response does not contain field ${this.options.user.property}`);
                    return Promise.reject(error);
                }

                this.$auth.setUser(userData);
                return response;
            })
            .catch((error) => {
                this.$auth.callOnError(error, {method: "fetchUser"});
                return Promise.reject(error);
            });
    }

    async logout() {
        // Sign out from AWS
        await CognitoAuth.signOut();

        // Reset auth data
        return this.$auth.reset();
    }

    reset({resetInterceptor = true} = {}): void {
        this.$auth.setUser(false);

        // Reset id token
        if (this.token) {
            this.token.reset();
            this.token = null;
        }

        // Reset refresh token
        if (this.refreshToken) {
            this.refreshToken.reset();
            this.refreshToken = null;
        }

        if (resetInterceptor) {
            this.requestHandler.reset();
        }
    }

    async _getCognitoUser() {
        return await CognitoAuth.currentAuthenticatedUser();
    }

    async _getCognitoSession() {
        return await CognitoAuth.currentSession();
    }

    async _refreshSession() {
        const user = await this._getCognitoUser();
        const {refreshToken} = user.getSignInUserSession();

        user.refreshSession(refreshToken, async (err: any) => {
            if (err) {
                throw new Error(err);
            }
        });

        return;
    }

    protected initializeRequestInterceptor(): void {
        this.requestHandler.initializeRequestInterceptor();
    }
}
