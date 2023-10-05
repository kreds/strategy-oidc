import {
  KredsAuthenticationOutcome,
  KredsStrategy,
  KredsStrategyOptions,
  KredsVerifyUserFunction,
  KredsContext,
  KredsClientAction,
} from '@kreds/types';

export interface OIDCAuthenticationStrategyConfig<TUser>
  extends KredsStrategyOptions<TUser> {
  client: {
    id: string;
    secret: string;
    redirectUrl: string;
    scopes: string[];
  };

  /**
   * URL of the server providing OpenID connect.
   * Excluding `.well-known/openid-configuration`
   */
  serverUrl: string;
  verify: KredsVerifyUserFunction<TUser, Data>;
}

interface Token {
  access_token: string;
  refresh_token?: string;
  token_type: string;
  expires_in: number;
  scope: string;
}

interface OIDCUserAddress {
  formatted?: string;
  street_address?: string;
  locality?: string;
  region?: string;
  postal_code?: string;
  country?: string;
}

interface OIDCUserInfo {
  sub: string;
  name?: string;
  given_name?: string;
  family_name?: string;
  middle_name?: string;
  nickname?: string;
  preferred_username?: string;
  profile?: string;
  picture?: string;
  website?: string;
  email?: string;
  email_verified?: boolean;
  gender?: string;
  birthdate?: string;
  zoneinfo?: string;
  locale?: string;
  phone_number?: string;
  phone_number_verified?: boolean;
  address?: OIDCUserAddress;
  updated_at?: number;
}

interface Data {
  token: Token;
  userInfo: OIDCUserInfo;
  expiresAt?: Date;
}

interface OpenIDConfiguration {
  authorization_endpoint?: string;
  token_endpoint?: string;
  userinfo_endpoint?: string;
}

export type OIDCAuthenticationPayload =
  | { code: string }
  | { access_token: string }
  | { refresh_token: string };
export type OIDCAuthenticationData = {};

export class OIDCAuthenticationStrategy<TUser> implements KredsStrategy<TUser> {
  readonly name = '-oidc';

  configuration: OpenIDConfiguration = {};

  constructor(private config: OIDCAuthenticationStrategyConfig<TUser>) {}

  private async init() {
    const url = new URL(
      '.well-known/openid-configuration',
      this.config.serverUrl
    );
    const res = await fetch(url);
    this.configuration = await res.json();
  }

  get action(): KredsClientAction {
    const url = this.redirectUrl;
    if (!url) {
      throw new Error(`No OpenID configuration for strategy ${this.name}.`);
    }

    return {
      type: 'redirect',
      url: this.redirectUrl,
    };
  }

  private get scope() {
    return this.config.client.scopes.join(' ');
  }

  private get redirectUrl() {
    const authorizeUrl = this.configuration.authorization_endpoint;
    if (!authorizeUrl) {
      return undefined;
    }

    const url = new URL(authorizeUrl);
    url.searchParams.append('response_type', 'code');
    url.searchParams.append('client_id', this.config.client.id);
    url.searchParams.append('scope', this.scope);
    url.searchParams.append('redirect_uri', this.config.client.redirectUrl);
    return url.href;
  }

  private async token(
    grantType: 'authorization_code' | 'refresh_token',
    code: string
  ): Promise<Token> {
    const url = this.configuration.token_endpoint;
    if (!url) {
      throw new Error(`No OpenID configuration for strategy ${this.name}.`);
    }

    try {
      const params = new URLSearchParams({
        client_id: this.config.client.id,
        client_secret: this.config.client.secret,
        grant_type: grantType,
        [grantType === 'authorization_code' ? 'code' : 'refresh_token']: code,
        redirect_uri: this.config.client.redirectUrl,
        scope: this.scope,
      });
      const res = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: params,
      });
      return await res.json();
    } catch (err) {
      console.trace(err);

      throw new Error(`Token endpoint responded with a non-OK status code.`);
    }
  }

  private async userinfo(token: Token): Promise<OIDCUserInfo> {
    const url = this.configuration.userinfo_endpoint;
    if (!url) {
      throw new Error(`No OpenID configuration for strategy ${this.name}.`);
    }

    try {
      const res = await fetch(url, {
        headers: {
          authorization: `${token.token_type} ${token.access_token}`,
        },
      });
      return await res.json();
    } catch (err) {
      console.trace(err);

      throw new Error(`UserInfo endpoint responded with a non-OK status code.`);
    }
  }

  async authenticate(
    context: KredsContext
  ): Promise<KredsAuthenticationOutcome<TUser> | undefined> {
    if (!context.payload) {
      return undefined;
    }

    const payload = context.payload as OIDCAuthenticationPayload;
    if (!payload) {
      return {
        done: false,
        action: this.action,
      };
    }

    if (!('code' in payload) && !('refresh_token' in payload)) {
      throw new Error('Not supported yet.');
    }

    const grantType =
      'code' in payload ? 'authorization_code' : 'refresh_token';
    const code =
      'code' in payload
        ? (payload as any).code
        : (payload as any).refresh_token;
    const token = await this.token(grantType, code);
    const userInfo = await this.userinfo(token);
    const expiresAt = new Date();
    expiresAt.setSeconds(expiresAt.getSeconds() + token.expires_in);
    return await this.config.verify(context, {
      token,
      userInfo,
      expiresAt,
    });
  }
}
