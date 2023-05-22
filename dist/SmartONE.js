"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.SmartONE = void 0;
const axios_1 = require("axios");
const axios_cookiejar_support_1 = require("axios-cookiejar-support");
const jsdom_1 = require("jsdom");
const jwt_decode_1 = require("jwt-decode");
const OpenID = require("openid-client");
const tough_cookie_1 = require("tough-cookie");
const qs = require("querystring");
const AUTH_URL = 'https://auth-us-east-1.smartone-solutions.com';
const API_URL = 'https://api-us-east-1.smartone-solutions.com';
const ENDPOINTS = {
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
class SmartONE {
    static _getClient() {
        return __awaiter(this, void 0, void 0, function* () {
            const issuer = yield OpenID.Issuer.discover(AUTH_URL);
            const client = new issuer.Client({
                client_id: 'bdf1af15-da1f-4389-b3eb-111e2feb00b6',
                client_secret: 'undefined', // this has to be any non-empty string
            });
            // SmartONE's auth server clock is a bit skewed, usually by 1 second
            // As precaution, using 10 seconds as tolerance
            client[OpenID.custom.clock_tolerance] = 10;
            // SmartONE's requests are too slow, and the default 3500ms fails very frequently
            // As precaution, using 10 seconds as timeout
            client[OpenID.custom.http_options] = (url, opts) => (Object.assign(Object.assign({}, opts), { timeout: 10000 }));
            return client;
        });
    }
    static _auth(authorizationUrl, username, password) {
        return __awaiter(this, void 0, void 0, function* () {
            const jar = new tough_cookie_1.CookieJar();
            const authService = (0, axios_cookiejar_support_1.wrapper)(axios_1.default.create({ baseURL: AUTH_URL, jar }));
            const res1 = yield authService.get(authorizationUrl);
            const dom1 = new jsdom_1.JSDOM(res1.data);
            const form = Object.fromEntries([...dom1.window.document.querySelectorAll('input')]
                .filter(el => !['Username', 'Password'].includes(el.name))
                .map(el => ([el.name, el.value])));
            form['Input.Username'] = username;
            form['Input.Password'] = password;
            form['Input.Button'] = 'login';
            const res2 = yield authService.post(res1.request.res.responseUrl, qs.stringify(form), {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            });
            if (!res2.data.includes('You are now being returned to the application')) {
                throw new Error('Login failed');
            }
            const dom2 = new jsdom_1.JSDOM(res2.data);
            const callbackUrl = dom2.window.document.querySelector('meta[http-equiv=refresh]').getAttribute('data-url');
            const res3 = yield authService.get(callbackUrl, { validateStatus: status => status === 302, maxRedirects: 0 });
            return res3.headers.location;
        });
    }
    static withCredentials(username, password) {
        return __awaiter(this, void 0, void 0, function* () {
            const client = yield SmartONE._getClient();
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
            const callbackUrl = yield SmartONE._auth(authorizationUrl, username, password);
            const params = client.callbackParams(callbackUrl);
            if (params.error) {
                throw new Error(`Login failed with: ${params.error}`);
            }
            const token = yield client.callback('smartone://login', params, {
                code_verifier: codeVerifier,
                state
            });
            return new SmartONE(client, token);
        });
    }
    static withRefreshToken(refreshToken) {
        return __awaiter(this, void 0, void 0, function* () {
            const client = yield SmartONE._getClient();
            const token = yield client.refresh(refreshToken);
            return new SmartONE(client, token);
        });
    }
    constructor(client, token) {
        this.client = client;
        this.token = token;
        this.tokenClaims = (0, jwt_decode_1.default)(token.id_token);
    }
    getToken() {
        return this.token;
    }
    refreshToken() {
        return __awaiter(this, void 0, void 0, function* () {
            this.token = yield this.client.refresh(this.token.refresh_token);
            return this.getToken();
        });
    }
    logout() {
        return __awaiter(this, void 0, void 0, function* () {
            yield this.client.revoke(this.token.access_token);
        });
    }
    request(endpoint, { method, headers, body } = {}, tokenRefreshed = false) {
        return __awaiter(this, void 0, void 0, function* () {
            const res = yield this.client.requestResource(endpoint, this.token, {
                method: method !== null && method !== void 0 ? method : 'GET',
                headers: Object.assign(Object.assign({}, headers), (method !== 'GET' ? { 'Content-Type': 'application/json' } : {})),
                body: JSON.stringify(body),
            });
            if (!tokenRefreshed && res.statusCode === 401) {
                yield this.refreshToken();
                return this.request(endpoint, { method, headers, body }, true);
            }
            if (res.statusCode >= 400) {
                throw new Error(`Request failed with ${res.statusCode} status code.`);
            }
            try {
                return JSON.parse(res.body.toString());
            }
            catch (_a) {
                return res.body;
            }
        });
    }
    getRegisterCode(resourceId, registrationPrerequirementsMet = false) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.request(ENDPOINTS.SMARTDEVICESERVICE_GETREGISTERCODE, {
                method: 'POST',
                body: {
                    resourceId,
                    registrationPrerequirementsMet,
                },
            });
        });
    }
    registerWithCode(resourceId, code) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.request(ENDPOINTS.SMARTDEVICESERVICE_REGISTERWITHCODE, {
                method: 'POST',
                body: {
                    resourceId,
                    code,
                    osCode: 'iOS',
                    mobileUUID: '0',
                },
            });
        });
    }
    unlink() {
        return __awaiter(this, void 0, void 0, function* () {
            return this.request(ENDPOINTS.SMARTDEVICESERVICE_REMOVEUSER, {
                method: 'DELETE'
            });
        });
    }
    getUser() {
        return __awaiter(this, void 0, void 0, function* () {
            return this.request(ENDPOINTS.USERMANAGEMENTSERVICE_GETUSER);
        });
    }
    smartdeviceServiceLogin(payload = {}) {
        return __awaiter(this, void 0, void 0, function* () {
            const defaultPayload = {
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
            return this.request(ENDPOINTS.SMARTDEVICESERVICE_LOGIN, {
                method: 'POST',
                body: Object.assign(Object.assign({}, defaultPayload), payload),
            });
        });
    }
    getNotifications() {
        return __awaiter(this, void 0, void 0, function* () {
            return this.request(ENDPOINTS.SMARTDEVICESERVICE_LISTNOTIFICATIONS);
        });
    }
    getSecuritySwitches() {
        return __awaiter(this, void 0, void 0, function* () {
            return this.request(ENDPOINTS.SMARTDEVICESERVICE_LISTSECURITYSWITCHES);
        });
    }
    getSecurityMode() {
        return __awaiter(this, void 0, void 0, function* () {
            const switches = yield this.getSecuritySwitches();
            const awaySwitch = switches.find(sw => sw.type === 'switch-awaySwitch');
            const preventSwitch = switches.find(sw => sw.type === 'switch-preventSwitch');
            if ((awaySwitch === null || awaySwitch === void 0 ? void 0 : awaySwitch.state) === 'off' && (preventSwitch === null || preventSwitch === void 0 ? void 0 : preventSwitch.state) === 'off') {
                return 'NONE';
            }
            if ((awaySwitch === null || awaySwitch === void 0 ? void 0 : awaySwitch.state) === 'on' && (preventSwitch === null || preventSwitch === void 0 ? void 0 : preventSwitch.state) === 'off') {
                return 'AWAY';
            }
            if ((awaySwitch === null || awaySwitch === void 0 ? void 0 : awaySwitch.state) === 'off' && (preventSwitch === null || preventSwitch === void 0 ? void 0 : preventSwitch.state) === 'on') {
                return 'STAY';
            }
            return 'UNKNOWN';
        });
    }
    setSecurityMode(mode) {
        return __awaiter(this, void 0, void 0, function* () {
            // SmartONE cannot switch between STAY and AWAY directly
            // it must disarm the security first
            if (['AWAY', 'STAY'].includes(mode)) {
                const currentMode = yield this.getSecurityMode();
                if (['AWAY', 'STAY'].includes(currentMode) && currentMode !== mode) {
                    yield this.request(ENDPOINTS.SMARTDEVICESERVICE_SETSECURITY, {
                        method: 'POST',
                        body: 'NONE',
                    });
                }
            }
            return this.request(ENDPOINTS.SMARTDEVICESERVICE_SETSECURITY, {
                method: 'POST',
                body: mode,
            });
        });
    }
    getDevices() {
        return __awaiter(this, void 0, void 0, function* () {
            return this.request(ENDPOINTS.SMARTDEVICESERVICE_LISTDEVICE);
        });
    }
    setDoorLock(deviceId, payload) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.request(ENDPOINTS.SMARTDEVICESERVICE_SETDOORLOCK, {
                method: 'POST',
                body: Object.assign({ deviceId }, payload),
            });
        });
    }
    setThermostat(deviceId, payload) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.request(ENDPOINTS.SMARTDEVICESERVICE_SETTHERMOSTAT, {
                method: 'POST',
                body: Object.assign({ deviceId }, payload),
            });
        });
    }
    getCameras() {
        return __awaiter(this, void 0, void 0, function* () {
            const response = yield this.request(ENDPOINTS.SMARTDEVICESERVICE_LISTCCTV, {
                method: 'POST',
            });
            return Object.entries(response.cctvs).reduce((allCCTVs, [buildingGuid, buildingCCTVs]) => [...allCCTVs, ...buildingCCTVs], []);
        });
    }
    getAvailableAccessPoints(buildingGuid) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.request(ENDPOINTS.ACCESSCONTROL_GETAVAILABLEACCESSPOINTS, {
                method: 'POST',
                body: {
                    userGuid: this.tokenClaims.user_id,
                    buildingGuid,
                },
            });
        });
    }
    getFavouriteAccessPoints() {
        return __awaiter(this, void 0, void 0, function* () {
            const response = yield this.request(ENDPOINTS.ACCESSCONTROL_GETACCESSPOINTS, {
                method: 'POST',
                body: {
                    userGuid: this.tokenClaims.user_id,
                },
            });
            return response.accessPoints;
        });
    }
    toggleFavouriteAccessPoint(accessPointGuid) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.request(ENDPOINTS.ACCESSCONTROL_TOGGLEFAVOURITECCESSPOINTS, {
                method: 'POST',
                body: {
                    userGuid: this.tokenClaims.user_id,
                    accessPointGuid,
                },
            });
        });
    }
}
exports.SmartONE = SmartONE;
