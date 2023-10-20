import {CognitoUserSession} from "amazon-cognito-identity-js";
import jwtDecode, {InvalidTokenError, type JwtPayload} from "jwt-decode";
import {TokenStatus} from "../../inc";
import {Storage} from "../..";
import {type RefreshTokenOptions} from "../../../types";

export interface CognitoRefreshTokenOption {
    name: string
    refreshToken: RefreshTokenOptions
}

export class CognitoRefreshToken {

    private readonly session: CognitoUserSession;
    private readonly refreshTokenOptions: CognitoRefreshTokenOption;
    private readonly storage: Storage;

    constructor(
        session: CognitoUserSession,
        refreshTokenOptions: CognitoRefreshTokenOption,
        storage: Storage
    ) {
        if (!session) {
            throw new Error("Cognito user session is required");
        }

        this.session = session;
        this.refreshTokenOptions = refreshTokenOptions;
        this.storage = storage;

        this._update();
    }

    _getExpiration() {
        const _key =
            this.refreshTokenOptions.refreshToken.expirationPrefix + this.refreshTokenOptions.name;
        return this.storage.getUniversal(_key);
    }

    _setExpiration(expiration: number | boolean) {
        const _key =
            this.refreshTokenOptions.refreshToken.expirationPrefix + this.refreshTokenOptions.name;
        return this.storage.setUniversal(_key, expiration);
    }

    _syncExpiration() {
        const _key =
            this.refreshTokenOptions.refreshToken.expirationPrefix + this.refreshTokenOptions.name;
        return this.storage.syncUniversal(_key);
    }

    _updateExpiration(refreshToken: string) {
        let refreshTokenExpiration: number;
        const _tokenIssuedAtMillis = Date.now();
        const _tokenTTLMillis =
            (this.refreshTokenOptions.refreshToken.maxAge as number) * 1000;
        const _tokenExpiresAtMillis = _tokenTTLMillis
            ? _tokenIssuedAtMillis + _tokenTTLMillis
            : 0;

        try {
            refreshTokenExpiration =
                jwtDecode<JwtPayload>(refreshToken as string).exp! * 1000 ||
                _tokenExpiresAtMillis;
        } catch (error) {
            // If the token is not jwt, we can't decode and refresh it, use _tokenExpiresAt value
            refreshTokenExpiration = _tokenExpiresAtMillis;
            if (!(error instanceof InvalidTokenError)) {
                throw error;
            }
        }

        // Set token expiration
        return this._setExpiration(refreshTokenExpiration || false);
    }

    _update() {
        const type = this.refreshTokenOptions.refreshToken.type;
        const token = (type ? type + " " : "") + this._getToken;

        this._updateExpiration(token);
        return token;
    }

    get _getToken() {
        return this.session.getRefreshToken().getToken();
    }

    set() {
        return this._update();
    }

    sync() {
        const token = this.get();

        this._syncExpiration();
        return token;
    }

    reset() {
        this._setExpiration(false);
    }

    status() {
        return new TokenStatus(this.get(), this._getExpiration());
    }

    get() {
        return this._getToken;
    }
}
