import {CognitoUserSession} from "amazon-cognito-identity-js";
import jwtDecode, {InvalidTokenError, type JwtPayload} from "jwt-decode";
import {RequestHandler, TokenStatus} from "../../inc";
import {Storage} from "../..";
import {type TokenOptions} from "../../../types";

export interface CognitoTokenOption {
    name: string
    token: TokenOptions
    requestHandler: RequestHandler
}

export class CognitoToken {
    private readonly session: CognitoUserSession;
    private readonly tokenOption: CognitoTokenOption;
    private readonly storage: Storage;

    constructor(
        session: CognitoUserSession,
        tokenOption: CognitoTokenOption,
        storage: Storage
    ) {
        if (!session) {
            throw new Error("Cognito user session is required");
        }

        this.session = session;
        this.tokenOption = tokenOption;
        this.storage = storage;

        this._update();
    }

    _getExpiration() {
        const _key = this.tokenOption.token.expirationPrefix + this.tokenOption.name;
        return this.storage.getUniversal(_key);
    }

    _setExpiration(expiration: number | boolean) {
        const _key = this.tokenOption.token.expirationPrefix + this.tokenOption.name;
        return this.storage.setUniversal(_key, expiration);
    }

    _syncExpiration() {
        const _key = this.tokenOption.token.expirationPrefix + this.tokenOption.name;
        return this.storage.syncUniversal(_key);
    }

    _updateExpiration(token: string) {
        let tokenExpiration;
        const _tokenIssuedAtMillis = Date.now();
        const _tokenTTLMillis = (this.tokenOption.token.maxAge as number) * 1000;
        const _tokenExpiresAtMillis = _tokenTTLMillis
            ? _tokenIssuedAtMillis + _tokenTTLMillis
            : 0;
        try {
            tokenExpiration =
                jwtDecode<JwtPayload>(token as string).exp! || _tokenExpiresAtMillis;
        } catch (error) {
            // If the token is not jwt, we can't decode and refresh it, use _tokenExpiresAt value
            tokenExpiration = _tokenExpiresAtMillis;
            if (!(error instanceof InvalidTokenError)) {
                throw error;
            }
        }

        // Set token expiration
        return this._setExpiration(tokenExpiration || false);
    }

    _update() {
        const type = this.tokenOption.token.type;
        const token = (type ? type + " " : "") + this._getToken;

        this._updateExpiration(token);

        if (typeof token === 'string') {
            this.tokenOption.requestHandler.setHeader(token);
        }

        return token;
    }

    get _getToken() {
        return this.session.getIdToken().getJwtToken();
    }

    set() {
        return this._update();
    }

    sync() {
        const type = this.tokenOption.token.type;
        const token = (type ? type + " " : "") + this._getToken;

        this._syncExpiration();

        if (typeof token === 'string') {
            this.tokenOption.requestHandler.setHeader(token);
        }

        return token;
    }

    reset() {
        this.tokenOption.requestHandler.clearHeader();
        this._setExpiration(false);
    }

    status() {
        return new TokenStatus(this.get(), this._getExpiration());
    }

    get() {
        return this._getToken;
    }
}
