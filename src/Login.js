import { Linking } from 'react-native';
import * as querystring from 'query-string';
import uuidv4 from 'uuid/v4';
import {
  WebView
} from 'react-native-webview';
import React from 'react';

try {
  let GoogleSignin = require("@react-native-community/google-signin");
} catch (e) {
  console.error("Google Signin is not found");
}
try {
  let FBSDK = require("react-native-fbsdk");
} catch (e) {
  console.error("Facebook SDK is not found");
}
try {
  let InAppBrowser = require("react-native-inappbrowser-reborn");
} catch (e) {
  console.error("InApp Browser is not found");
}
try {
  let AppleAuth = require("@invertase/react-native-apple-authentication");
  console.log("Apple Auth");
  console.log(AppleAuth);
} catch (e) {
  console.error("Apple auth is not found");
}

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
    let params = {};
    params['grant_type'] = 'urn:ietf:params:oauth:grant-type:token-exchange';
    params['subject_token_type'] = 'urn:ietf:params:oauth:token-type:' + tokenType;
    params['client_id'] = conf.clientId;
    params['subject_issuer'] = issuer;
    params['subject_token'] = token;

    return params;
  }

  async FBLogin(conf) {
    this.setConf(conf);
    const { url, state } = this.getLoginURL();
    let result = await FBSDK.LoginManager.logInWithPermissions(["public_profile", "email"]);
    let currentToken = await FBSDK.AccessToken.getCurrentAccessToken();
    let params = await this.generateParams(conf, "access_token", "facebook", currentToken.accessToken);
    this.props.url = `${this.getRealmURL()}/protocol/openid-connect/token`;
    this.setRequestOptions(
      'POST',
      querystring.stringify(params),
    );
    const fullResponse = await fetch(this.props.url, this.props.requestOptions);
    const jsonResponse = await fullResponse.json();

    if (fullResponse.ok) {
      jsonResponse.id_token = jsonResponse.access_token;

      await this.tokenStorage.saveTokens(jsonResponse);
      return jsonResponse;
    } else if (jsonResponse.error_description === "User already exists") {
      throw { name: "WrongPlatformError", message: "Please sign in with the correct social media platform" };
    }
    else {
      throw { name: "ResponseError", message: "Something went wrong with the response" };
    }
  }

  async GoogleLogin(conf) {
    this.setConf(conf);
    const { url, state } = this.getLoginURL();
    GoogleSignin.GoogleSignin.configure();
    const userInfo = await GoogleSignin.GoogleSignin.signIn();
    let tokenInfo = await GoogleSignin.GoogleSignin.getTokens();
    let params = await this.generateParams(conf, "access_token", "google", tokenInfo.accessToken);
    this.props.url = `${this.getRealmURL()}/protocol/openid-connect/token`;
    this.setRequestOptions(
      'POST',
      querystring.stringify(params),
    );
    const fullResponse = await fetch(this.props.url, this.props.requestOptions);
    const jsonResponse = await fullResponse.json();

    let responseText = await fullResponse.json();

    if (fullResponse.ok) {
      jsonResponse.id_token = jsonResponse.access_token;

      await this.tokenStorage.saveTokens(jsonResponse);
      return jsonResponse;
    } else if (jsonResponse.error_description === "User already exists") {
      throw { name: "WrongPlatformError", message: "Please sign in with the correct social media platform" };
    }
    else {
      throw { name: "ResponseError", message: "Something went wrong with the response" };
    }
  }

  async AppleLogin(conf) {
    this.setConf(conf);
    const { url, state } = this.getLoginURL();
    const appleAuthRequestResponse = await AppleAuth.appleAuth.performRequest({
      requestedOperation: AppleAuthRequestOperation.LOGIN,
      requestedScopes: [AppleAuthRequestScope.EMAIL, AppleAuthRequestScope.FULL_NAME],
    });
    let code = appleAuthRequestResponse.authorizationCode;
    let token = appleAuthRequestResponse.identityToken;
    await this.tokenStorage.saveTokens(appleAuthRequestResponse.identityToken);
    let params = await this.generateParams(conf, "id_token", "apple", token);
    this.props.url = `${this.getRealmURL()}/protocol/openid-connect/token`;
    this.setRequestOptions(
      'POST',
      querystring.stringify(params),
    );
    const fullResponse = await fetch(this.props.url, this.props.requestOptions);
    const jsonResponse = await fullResponse.json();

    if (fullResponse.ok) {
      jsonResponse.id_token = jsonResponse.access_token;

      await this.tokenStorage.saveTokens(jsonResponse);
      return jsonResponse;
    } else if (jsonResponse.error_description === "User already exists") {
      throw { name: "WrongPlatformError", message: "Please sign in with the correct social media platform" };
    }
    else {
      throw { name: "ResponseError", message: "Something went wrong with the response" };
    }
  }

  getTokens() {
    return this.tokenStorage.loadTokens();
  }

  async startLoginProcess(conf) {
    this.setConf(conf);
    return new Promise(((resolve, reject) => {
      const { url, state } = this.getLoginURL();
      this.state = {
        ...this.state,
        resolve,
        reject,
        state,
      };
      if (InAppBrowser) {
        InAppBrowser.default.open(url);
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
    if (LoginManager) {
      await LoginManager.logOut();
    }
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
    console.log("TRUE JSON RESPONSE");
    console.log(jsonResponse);
    if (fullResponse.ok) {
      this.tokenStorage.saveTokens(jsonResponse);
      this.state.resolve(jsonResponse);
    } else {
      this.state.reject(jsonResponse);
    }
    if (InAppBrowser) {
      InAppBrowser.default.close();
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
