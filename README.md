> Alternative Auth module for [Nuxt](https://nuxt.com)

## Info

This module is meant as an alternative to @nuxtjs/auth with a focus on support for Amazon Cognito, forked from [nuxt-alt/auth](https://github.com/nuxt-alt/auth).

## Setup

1. Add `@toyopilgrim/nuxt-alt-auth` `@pinia/nuxt` `pinia` and `@nuxt-alt/http` dependency to your project

```bash
yarn add @toyopilgrim/nuxt-alt-auth @nuxt-alt/http @pinia/nuxt pinia
```

2. Add `@toyopilgrim/nuxt-alt-auth` and `@pinia/nuxt` to the `modules` section of `nuxt.config.ts`

**Note:** you dont need to specify `@nuxt-alt/http`, it will automatically be added but if you want to manually add it, make sure it is below the auth module (and above the proxy module if you are using it)

```ts
export default defineNuxtConfig({
    modules: [
        '@toyopilgrim/nuxt-alt-auth',
        '@pinia/nuxt'
    ],
    auth: {
        /* cognit options */
        strategies: {
            cognito: {
                scheme: "cognito",
                credentials: {
                    userPoolId: process.env.COGNITO_USERPOOL_ID,
                    userPoolWebClientId: process.env.AUTH_CLIENT_ID,
                    region: process.env.COGNITO_REGION
                },
                endpoints: {
                    user: false
                }
            }
        }
    }
});

```

## Changes 

The module now uses '@nuxt-alt/http' to function, that module extends ohmyfetch. Please note that if you were using `data` to post data, you now need to use `body` since this is what `ohmyfetch` uses. If you intend to use ssr, please consider using the `@nuxt-alt/proxy` module.

## Composable

A `useAuth()` composable is availale to use to access the auth methods.

## Options
Most of the options are taken directly from the [@nuxtjs/auth](https://auth.nuxtjs.org/api/options) module. In addition there are some extra options available.

### `globalMiddleware`

- Type: `Boolean`
- Default: `false`

Enables/disables the middleware to be used globally.

### `enableMiddleware`

- Type: `Boolean`
- Default: `true`

Enables/disables the built-in middleware.

### `pinia.namespace`

- Type: `String`
- Default: `auth`

Changed from vuex to pinia, this is the namespace to use for the pinia store.

### `sessionStorage`

- Type: `String | False`
- Default: `auth.`

Similar to the localstorage option, there is a session storage options available for you to use.

### `routerStrategy`

- Type: `router | navigateTo`
- Default: `router`

By default it will use `router` (`navigateTo` has an issue; I'm assuming with SSR that I don't have the time to check into at the moment, but I'll eventually want to replace with at some point.)

### `redirectStrategy`

- Type: `query | storage`
- Default: `storage`

The type of redirection strategy you want to use, `storage` utilizng localStorage for redirects, `query` utilizing the route query parameters.

## Tokens (Types)

In addition to [Auth Tokens](https://auth.nuxtjs.org/api/tokens);

By default the `$auth.strategy` getter uses the `Scheme` type which does not have `token` or `refreshToken` property types. To help with this, a `$auth.refreshStrategy` and a `$auth.tokenStrategy` getter have been added for typing. They all do the same thing, this is just meant for type hinting.

## Cookie-based auth (Update: 2.5.0+)

The cookie scheme has been decoupled from the local scheme as it does not utitlize tokens, rather it it uses cookies.

~~There is a new `cookie.server` property, this indicates that the cookie we will be looking for will be set upon login otherwise we will be looking at a client/browser cookie. There has also been 2 user properties one for the client/browser and one for the server. An example config looks like this:~~

The `cookie.server` param has been removed. This was meant as a workaround to decouple the server and client user request when logging in because the check was being overriden. This should be fixed in 2.5.0. The `user.property` param no longer needs to be separated by server and client so use `user.property` instead of `user.property.server` and `user.property.client`.

## TypeScript (2.6.0+)

The user information can be edited like so for TypeScript:

```ts
declare module '@nuxt-alt/auth' {
    interface UserInfo {
        email: string
        name: string
    }
}
```

## Oauth2

Oauth2 now has client window authentication thanks to this pull request: https://github.com/nuxt-community/auth-module/pull/1746 

Properties have been changed to:

### `clientWindow`

- Type: `Boolean`
- Default: `false`

Enable/disable the use of a popup for client authentication.

### `clientWidth`

- Type: `Number`
- Default: `400`

The width of the client window.

### `clientHieght`

- Type: `Number`
- Default: `600`

The width of the client window.

## Aliases
Available aliases to use within nuxt

- `#auth/runtime`
- `#auth/utils`
- `#auth/providers`
