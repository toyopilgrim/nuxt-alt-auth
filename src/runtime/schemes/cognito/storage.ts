import { Storage } from "../..";

export class CognitoStorage /* implements ICognitoStorage */ {
  private readonly storage: Storage;
  private readonly clientId: string;

  constructor(storage: Storage, clientId: string) {
    this.storage = storage;
    this.clientId = clientId;
  }

  setItem(key: string, value: any) {
    this.storage.setUniversal(key, value);
  }

  getItem(key: string) {
    return this.storage.getUniversal(key);
  }

  removeItem(key: string) {
    this.storage.removeUniversal(key);
  }

  clear() {
    let prefix = `auth.CognitoIdentityServiceProvider.${this.clientId}.`;
    const lastAuthUser = this.getItem(prefix + "LastAuthUser");

    if (!lastAuthUser) {
      return;
    }

    this.removeItem(prefix + "LastAuthUser");
    ["accessToken", "clockDrift", "idToken", "refreshToken"]
      .map((name) => `${prefix}${lastAuthUser}.${name}`)
      .map((name) => this.removeItem(name));
  }
}
