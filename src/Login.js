import { Linking } from 'react-native';
import * as querystring from 'query-string';
import uuidv4 from 'uuid/v4';
import {
  WebView
} from 'react-native-webview';
import React from 'react';
import appleAuth, {
  AppleAuthRequestOperation,
  AppleAuthRequestScope,
  AppleAuthCredentialState,
} from '@invertase/react-native-apple-authentication';
let InAppBrowser = require("react-native-inappbrowser-reborn");
let FBSDK = require("react-native-fbsdk");
let GoogleSignIn = require("react-native-google-signin");

export class Login {
  state;
  conf;
  tokenStorage;

  constructor() {
    this.state = {};
    this.onOpenURL = this.onOpenURL.bind(this);
    Linking.addEventListener('url', this.onOpenURL);

    this.props = {
      requestOptions: {
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        method: 'GET',
        body: undefined,
      },
      url: '',
    };
  }

  async generateParams(conf, tokenType, issuer, token) {
    const params = new URLSearchParams();
    params.append('grant_type', 'urn:ietf:params:oauth:grant-type:token-exchange');
    params.append('subject_token_type', 'urn:ietf:params:oauth:token-type:' + tokenType);
    params.append('client_id', conf.clientId);
    params.append('subject_issuer', issuer);
    params.append('subject_token', token);
    return params;
  }

  async FBLogin(conf) {
    this.setConf(conf);
    const { url, state } = this.getLoginURL();
    let result = await LoginManager.logInWithPermissions(["public_profile", "email"]);
    let token = await AccessToken.getCurrentAccessToken();
    let params = generateParams(conf, "access_token", "facebook", token);
    this.props.url = `${this.getRealmURL()}/protocol/openid-connect/token`;
    this.setRequestOptions(
      'POST',
      querystring.stringify(params),
    );
    const fullResponse = await fetch(this.props.url, this.props.requestOptions);
    console.log("FULL RESPONSE FB");
    console.log(fullResponse);
  }

  async GoogleLogin(conf) {
    this.setConf(conf);
    const { url, state } = this.getLoginURL();
    let params = generateParams(conf, "access_token", "google");
  }

  async AppleLogin(conf) {
    this.setConf(conf);
    const { url, state } = this.getLoginURL();
    const appleAuthRequestResponse = await appleAuth.performRequest({
      requestedOperation: AppleAuthRequestOperation.LOGIN,
      requestedScopes: [AppleAuthRequestScope.EMAIL, AppleAuthRequestScope.FULL_NAME],
    });
    let token = appleAuthRequestResponse.identityToken;
    let params = generateParams(conf, "id_token", "apple", token);
    this.props.url = `${this.getRealmURL()}/protocol/openid-connect/token`;
    this.setRequestOptions(
      'POST',
      querystring.stringify(params),
    );
    const fullResponse = await fetch(this.props.url, this.props.requestOptions);
    console.log("FULL RESPONSE Apple");
    console.log(fullResponse);
    let json = await fullResponse.json();
    console.log(json);
  }

  getTokens() {
    return this.tokenStorage.loadTokens();
  }

  async startLoginProcess(conf) {
    this.setConf(conf);
    return new Promise(((resolve, reject) => {
      const { url, state } = this.getLoginURL();
      console.log("login process state");
      console.log(state);
      this.state = {
        ...this.state,
        resolve,
        reject,
        state,
      };
      console.log("url");
      console.log(url);
      if (InAppBrowser && await InAppBrowser.isAvailable()) {
        await InAppBrowser.open(url);
      }
      else {
        Linking.openURL(url);
      }
    }));
  }

  setConf(conf) {
    if (conf) {
      this.conf = conf;
    }
  }

  async logoutKc() {
    const { clientId } = this.conf;
    const savedTokens = await this.getTokens();
    if (!savedTokens) {
      return undefined;
    }

    this.props.url = `${this.getRealmURL()}/protocol/openid-connect/logout`;

    this.setRequestOptions(
      'POST',
      querystring.stringify({ client_id: clientId, refresh_token: savedTokens.refresh_token }),
    );

    const fullResponse = await fetch(this.props.url, this.props.requestOptions);

    if (fullResponse.ok) {
      this.tokenStorage.clearTokens();
      return true;
    }
    return false;
  }

  onOpenURL(event) {
    if (typeof this.conf === 'undefined') {
      return;
    }
    if (event.url.startsWith(this.conf.appsiteUri)) {
      const {
        state,
        code,
      } = querystring.parse(querystring.extract(event.url));
      console.log(state);
      console.log(this.state.state);
      if (this.state.state === state) {
        this.retrieveTokens(code);
      }
    }
  }

  async retrieveTokens(code) {
    const { redirectUri, clientId } = this.conf;
    this.props.url = `${this.getRealmURL()}/protocol/openid-connect/token`;

    // Cleans off hashes and everything after in order to keep clean code
    code = code.split('#')[0];

    this.setRequestOptions(
      'POST',
      querystring.stringify({
        grant_type: 'authorization_code', redirect_uri: redirectUri, client_id: clientId, code,
      }),
    );

    const fullResponse = await fetch(this.props.url, this.props.requestOptions);
    const jsonResponse = await fullResponse.json();
    if (fullResponse.ok) {
      this.tokenStorage.saveTokens(jsonResponse);
      this.state.resolve(jsonResponse);
    } else {
      this.state.reject(jsonResponse);
    }
    if (InAppBrowser && await InAppBrowser.isAvailable()) {
      InAppBrowser.close();
    }
  }

  async retrieveUserInfo(conf) {
    this.setConf(conf);
    const savedTokens = await this.getTokens();
    if (savedTokens) {
      this.props.url = `${this.getRealmURL()}/protocol/openid-connect/userinfo`;

      this.setHeader('Authorization', `Bearer ${savedTokens.access_token}`);
      this.setRequestOptions('GET');

      const fullResponse = await fetch(this.props.url, this.props.requestOptions);
      if (fullResponse.ok) {
        return fullResponse.json();
      }
    }
    return undefined;
  }

  async refreshToken() {
    const savedTokens = await this.getTokens();
    if (!savedTokens) {
      return undefined;
    }

    const { clientId } = this.conf;
    this.props.url = `${this.getRealmURL()}/protocol/openid-connect/token`;

    this.setRequestOptions('POST', querystring.stringify({
      grant_type: 'refresh_token',
      refresh_token: savedTokens.refresh_token,
      client_id: encodeURIComponent(clientId),
    }));

    const fullResponse = await fetch(this.props.url, this.props.requestOptions);
    if (fullResponse.ok) {
      const jsonResponse = await fullResponse.json();
      this.tokenStorage.saveTokens(jsonResponse);
      return jsonResponse;
    }
    return undefined;
  }

  getRealmURL() {
    const { url, realm } = this.conf;
    const slash = url.endsWith('/') ? '' : '/';
    return `${url + slash}realms/${encodeURIComponent(realm)}`;
  }

  getLoginURL() {
    const { redirectUri, clientId, kcIdpHint } = this.conf;
    const responseType = 'code';
    const state = uuidv4();
    const scope = 'openid';
    const url = `${this.getRealmURL()}/protocol/openid-connect/auth?${querystring.stringify({
      scope,
      kc_idp_hint: kcIdpHint,
      redirect_uri: redirectUri,
      client_id: clientId,
      response_type: responseType,
      state,
    })}`;

    return {
      url,
      state,
    };
  }

  setTokenStorage(tokenStorage) {
    this.tokenStorage = tokenStorage;
  }

  setRequestOptions(method, body) {
    this.props.requestOptions = {
      ...this.props.requestOptions,
      method,
      body,
    };
  }

  setHeader(key, value) {
    this.props.requestOptions.headers[key] = value;
  }
}
