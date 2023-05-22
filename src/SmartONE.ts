import Axios from 'axios';
import { wrapper } from 'axios-cookiejar-support';
import { JSDOM } from 'jsdom';
import JWTDecode from 'jwt-decode';
import * as OpenID from 'openid-client';
import { CookieJar } from 'tough-cookie';
import * as qs from 'querystring';

import {
  AccessPoint,
  Camera,
  DeviceDetectSensor,
  DeviceDoorLock,
  DeviceThermostat,
  RequestSetDevice,
  RequestSetThermostat,
  RequestSmartDeviceServiceLogin,
  ResponseDeviceSet,
  ResponseDeviceSetWithMQTT,
  ResponseGetRegisterCode,
  ResponseGetUser,
  ResponseRegisterWithCode,
  ResponseSmartDeviceServiceLogin,
  SecurityMode,
  SecuritySwitch,
} from './types';

const AUTH_URL = 'https://auth-us-east-1.smartone-solutions.com';
const API_URL = 'https://api-us-east-1.smartone-solutions.com';

const ENDPOINTS: { [key: string]: string } = {
  USERMANAGEMENTSERVICE_GETUSER: `${API_URL}/UserManagementService/users/signed-in`,
  SMARTDEVICESERVICE_LOGIN: `${API_URL}/SmartDeviceService/api/users/login`,

  SMARTDEVICESERVICE_GETREGISTERCODE: `${API_URL}/SmartDeviceService/api/users/GetRegisterCode`,
  SMARTDEVICESERVICE_REGISTERWITHCODE: `${API_URL}/SmartDeviceService/api/Users/RegisterWithCode`,
  SMARTDEVICESERVICE_REMOVEUSER: `${API_URL}/SmartDeviceService/api/users/remove`,

  SMARTDEVICESERVICE_LISTNOTIFICATIONS: `${API_URL}/SmartDeviceService/api/notifications`,

  SMARTDEVICESERVICE_LISTSECURITYSWITCHES: `${API_URL}/SmartDeviceService/api/Security/switches`,
  SMARTDEVICESERVICE_SETSECURITY: `${API_URL}/SmartDeviceService/api/Security/Mode`,

  SMARTDEVICESERVICE_LISTDEVICE: `${API_URL}/SmartDeviceService/api/devices/list`,
  SMARTDEVICESERVICE_SETDOORLOCK: `${API_URL}/SmartDeviceService/api/Devices/doorLock/set`,
  SMARTDEVICESERVICE_SETTHERMOSTAT: `${API_URL}/SmartDeviceService/api/Devices/thermostat/set`,

  SMARTDEVICESERVICE_LISTCCTV: `${API_URL}/SmartDeviceService/api/CCTV`,

  ACCESSCONTROL_GETAVAILABLEACCESSPOINTS: `${API_URL}/AccessControl/api/Access/GetAvailableAccessPoints`,
  ACCESSCONTROL_GETFAVOURITECCESSPOINTS: `${API_URL}/AccessControl/api/User/GetFavouriteAccessPoints`,
  ACCESSCONTROL_TOGGLEFAVOURITECCESSPOINTS: `${API_URL}/AccessControl/api/User/ToggleFavouriteAccessPoint`,
};

type Method = 'GET' | 'POST' | 'PUT' | 'HEAD' | 'DELETE' | 'OPTIONS' | 'TRACE' | 'PATCH';

export class SmartONE {
  private static async _getClient(): Promise<OpenID.Client> {
    const issuer = await OpenID.Issuer.discover(AUTH_URL);
    const client = new issuer.Client({
      client_id: 'bdf1af15-da1f-4389-b3eb-111e2feb00b6',
      client_secret: 'undefined', // this has to be any non-empty string
    });

    // SmartONE's auth server clock is a bit skewed, usually by 1 second
    // As precaution, using 10 seconds as tolerance
    client[OpenID.custom.clock_tolerance] = 10;
    // SmartONE's requests are too slow, and the default 3500ms fails very frequently
    // As precaution, using 10 seconds as timeout
    client[OpenID.custom.http_options] = (url, opts) => ({
      ...opts,
      timeout: 10000,
    });

    return client;
  }

  private static async _auth(authorizationUrl: string, username: string, password: string): Promise<string> {
    const jar = new CookieJar();
    const authService = wrapper(Axios.create({ baseURL: AUTH_URL, jar }));

    const res1 = await authService.get(authorizationUrl);
    const dom1 = new JSDOM(res1.data);
    const form = Object.fromEntries(
      [...dom1.window.document.querySelectorAll('input')]
        .filter(el => !['Username', 'Password'].includes(el.name))
        .map(el => ([el.name, el.value]))
    );
    form['Input.Username'] = username;
    form['Input.Password'] = password;
    form['Input.Button'] = 'login';

    const res2 = await authService.post(res1.request.res.responseUrl, qs.stringify(form), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    });
    if (!res2.data.includes('You are now being returned to the application')) {
      throw new Error('Login failed');
    }

    const dom2 = new JSDOM(res2.data);
    const callbackUrl = dom2.window.document.querySelector('meta[http-equiv=refresh]').getAttribute('data-url');

    const res3 = await authService.get(callbackUrl, { validateStatus: status => status === 302, maxRedirects: 0 });

    return res3.headers.location;
  }

  static async withCredentials(username: string, password: string) {
    const client = await SmartONE._getClient();
    const codeVerifier = OpenID.generators.codeVerifier();
    const codeChallenge = OpenID.generators.codeChallenge(codeVerifier);
    const state = OpenID.generators.state();

    const authParams = {
      response_type: 'code',
      redirect_uri: 'smartone://login',
      scope: 'offline_access openid profile email ApiGateway',
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      state,
    };
    const authorizationUrl = client.authorizationUrl(authParams);

    const callbackUrl = await SmartONE._auth(authorizationUrl, username, password);
    const params = client.callbackParams(callbackUrl);
    if (params.error) {
      throw new Error(`Login failed with: ${params.error}`);
    }

    const token = await client.callback('smartone://login', params, {
      code_verifier: codeVerifier,
      state
    });

    return new SmartONE(client, token);
  }

  static async withRefreshToken(refreshToken: string) {
    const client = await SmartONE._getClient();
    const token = await client.refresh(refreshToken);

    return new SmartONE(client, token);
  }

  private client: OpenID.BaseClient;
  private token: OpenID.TokenSet;
  private tokenClaims: {
    user_id: string;
    username: string;
    email: string;
    given_name: string;
    family_name: string;
  }

  constructor(client: OpenID.BaseClient, token: OpenID.TokenSet) {
    this.client = client;
    this.token = token;
    this.tokenClaims = JWTDecode(token.id_token);
  }

  getToken() {
    return this.token;
  }

  async refreshToken() {
    this.token = await this.client.refresh(this.token.refresh_token);

    return this.getToken();
  }

  async logout() {
    await this.client.revoke(this.token.access_token);
  }

  async request<T = any>(endpoint: string, { method, headers, body }: { method?: Method, headers?: string[], body?: any } = {}, tokenRefreshed = false): Promise<T> {
    const res = await this.client.requestResource(endpoint, this.token, {
      method: method ?? 'GET',
      headers: {
        ...headers,
        ...(method !== 'GET' ? { 'Content-Type': 'application/json' } : {}),
      },
      body: JSON.stringify(body),
    });

    if (!tokenRefreshed && res.statusCode === 401) {
      await this.refreshToken();
      return this.request(endpoint, { method, headers, body }, true);
    }

    if (res.statusCode >= 400) {
      throw new Error(`Request failed with ${res.statusCode} status code.`);
    }

    try {
      return JSON.parse(res.body.toString()) as T;
    } catch {
      return res.body as T;
    }
  }

  async getRegisterCode(resourceId: string, registrationPrerequirementsMet: boolean = false) {
    return this.request<ResponseGetRegisterCode>(ENDPOINTS.SMARTDEVICESERVICE_GETREGISTERCODE, {
      method: 'POST',
      body: {
        resourceId,
        registrationPrerequirementsMet,
      },
    });
  }

  async registerWithCode(resourceId: string, code: string) {
    return this.request<ResponseRegisterWithCode>(ENDPOINTS.SMARTDEVICESERVICE_REGISTERWITHCODE, {
      method: 'POST',
      body: {
        resourceId,
        code,
        osCode: 'iOS',
        mobileUUID: '0',
      },
    });
  }

  async unlink() {
    return this.request<void>(ENDPOINTS.SMARTDEVICESERVICE_REMOVEUSER, {
      method: 'DELETE'
    });
  }

  async getUser() {
    return this.request<ResponseGetUser>(ENDPOINTS.USERMANAGEMENTSERVICE_GETUSER);
  }

  async smartdeviceServiceLogin(payload: RequestSmartDeviceServiceLogin = {}) {
    const defaultPayload: RequestSmartDeviceServiceLogin = {
      debugYn: 'Y',
      mobileUuid: '0',
      appVersion: '0',
      deviceName: '0',
      osType: 'iOS',
      osVersion: '0',
      pushTokenId: 'solutions.smartone',
      pushToken: '',
      voipToken: '',
    };

    return this.request<ResponseSmartDeviceServiceLogin>(ENDPOINTS.SMARTDEVICESERVICE_LOGIN, {
      method: 'POST',
      body: {
        ...defaultPayload,
        ...payload,
      },
    });
  }

  async getNotifications() {
    return this.request<Notification[]>(ENDPOINTS.SMARTDEVICESERVICE_LISTNOTIFICATIONS);
  }

  async getSecuritySwitches() {
    return this.request<SecuritySwitch[]>(ENDPOINTS.SMARTDEVICESERVICE_LISTSECURITYSWITCHES);
  }

  async getSecurityMode(): Promise<SecurityMode> {
    const switches = await this.getSecuritySwitches();

    const awaySwitch = switches.find(sw => sw.type === 'switch-awaySwitch');
    const preventSwitch = switches.find(sw => sw.type === 'switch-preventSwitch');

    if (awaySwitch?.state === 'off' && preventSwitch?.state === 'off') {
      return 'NONE';
    }

    if (awaySwitch?.state === 'on' && preventSwitch?.state === 'off') {
      return 'AWAY';
    }

    if (awaySwitch?.state === 'off' && preventSwitch?.state === 'on') {
      return 'STAY';
    }

    return 'UNKNOWN';
  }

  async setSecurityMode(mode: Exclude<SecurityMode, 'UNKNOWN'>) {
    // SmartONE cannot switch between STAY and AWAY directly
    // it must disarm the security first
    if (['AWAY', 'STAY'].includes(mode)) {
      const currentMode = await this.getSecurityMode();
      if (['AWAY', 'STAY'].includes(currentMode) && currentMode !== mode) {
        await this.request<'success'>(ENDPOINTS.SMARTDEVICESERVICE_SETSECURITY, {
          method: 'POST',
          body: 'NONE',
        });
      }
    }

    return this.request<'success'>(ENDPOINTS.SMARTDEVICESERVICE_SETSECURITY, {
      method: 'POST',
      body: mode,
    });
  }

  async getDevices() {
    return this.request<{
      devices: Array<DeviceThermostat | DeviceDetectSensor | DeviceDoorLock>;
      securityMode: string;
      doorMode: string;
      lockMode: string;
    }>(ENDPOINTS.SMARTDEVICESERVICE_LISTDEVICE);
  }

  async setDoorLock(deviceId: string, payload: RequestSetDevice) {
    return this.request<ResponseDeviceSet>(ENDPOINTS.SMARTDEVICESERVICE_SETDOORLOCK, {
      method: 'POST',
      body: {
        deviceId,
        ...payload,
      },
    });
  }

  async setThermostat(deviceId: string, payload: RequestSetThermostat) {
    return this.request<ResponseDeviceSetWithMQTT>(ENDPOINTS.SMARTDEVICESERVICE_SETTHERMOSTAT, {
      method: 'POST',
      body: {
        deviceId,
        ...payload,
      },
    });
  }

  async getCameras() {
    const response = await this.request<{ cctvs: { [buildingGuid: string]: Camera[] } }>(ENDPOINTS.SMARTDEVICESERVICE_LISTCCTV, {
      method: 'POST',
    });

    return Object.entries(response.cctvs).reduce((allCCTVs, [buildingGuid, buildingCCTVs]) => [...allCCTVs, ...buildingCCTVs], [] as Camera[]);
  }

  async getAvailableAccessPoints(buildingGuid: string) {
    return this.request<AccessPoint[]>(ENDPOINTS.ACCESSCONTROL_GETAVAILABLEACCESSPOINTS, {
      method: 'POST',
      body: {
        userGuid: this.tokenClaims.user_id,
        buildingGuid,
      },
    });
  }

  async getFavouriteAccessPoints() {
    const response = await this.request<{ accessPoints: AccessPoint[] }>(ENDPOINTS.ACCESSCONTROL_GETACCESSPOINTS, {
      method: 'POST',
      body: {
        userGuid: this.tokenClaims.user_id,
      },
    });

    return response.accessPoints;
  }

  async toggleFavouriteAccessPoint(accessPointGuid: string) {
    return this.request<void>(ENDPOINTS.ACCESSCONTROL_TOGGLEFAVOURITECCESSPOINTS, {
      method: 'POST',
      body: {
        userGuid: this.tokenClaims.user_id,
        accessPointGuid,
      },
    });
  }
}
