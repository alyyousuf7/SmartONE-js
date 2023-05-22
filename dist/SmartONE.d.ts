import * as OpenID from 'openid-client';
import { AccessPoint, Camera, DeviceDetectSensor, DeviceDoorLock, DeviceThermostat, RequestSetDevice, RequestSetThermostat, RequestSmartDeviceServiceLogin, ResponseDeviceSet, ResponseDeviceSetWithMQTT, ResponseGetRegisterCode, ResponseGetUser, ResponseRegisterWithCode, ResponseSmartDeviceServiceLogin, SecurityMode, SecuritySwitch } from './types';
type Method = 'GET' | 'POST' | 'PUT' | 'HEAD' | 'DELETE' | 'OPTIONS' | 'TRACE' | 'PATCH';
export declare class SmartONE {
    private static _getClient;
    private static _auth;
    static withCredentials(username: string, password: string): Promise<SmartONE>;
    static withRefreshToken(refreshToken: string): Promise<SmartONE>;
    private client;
    private token;
    private tokenClaims;
    constructor(client: OpenID.BaseClient, token: OpenID.TokenSet);
    getToken(): OpenID.TokenSet;
    refreshToken(): Promise<OpenID.TokenSet>;
    logout(): Promise<void>;
    request<T = any>(endpoint: string, { method, headers, body }?: {
        method?: Method;
        headers?: string[];
        body?: any;
    }, tokenRefreshed?: boolean): Promise<T>;
    getRegisterCode(resourceId: string, registrationPrerequirementsMet?: boolean): Promise<ResponseGetRegisterCode>;
    registerWithCode(resourceId: string, code: string): Promise<ResponseRegisterWithCode>;
    unlink(): Promise<void>;
    getUser(): Promise<ResponseGetUser>;
    smartdeviceServiceLogin(payload?: RequestSmartDeviceServiceLogin): Promise<ResponseSmartDeviceServiceLogin>;
    getNotifications(): Promise<Notification[]>;
    getSecuritySwitches(): Promise<SecuritySwitch[]>;
    getSecurityMode(): Promise<SecurityMode>;
    setSecurityMode(mode: Exclude<SecurityMode, 'UNKNOWN'>): Promise<"success">;
    getDevices(): Promise<{
        devices: Array<DeviceThermostat | DeviceDetectSensor | DeviceDoorLock>;
        securityMode: string;
        doorMode: string;
        lockMode: string;
    }>;
    setDoorLock(deviceId: string, payload: RequestSetDevice): Promise<ResponseDeviceSet>;
    setThermostat(deviceId: string, payload: RequestSetThermostat): Promise<ResponseDeviceSetWithMQTT>;
    getCameras(): Promise<Camera[]>;
    getAvailableAccessPoints(buildingGuid: string): Promise<AccessPoint[]>;
    getFavouriteAccessPoints(): Promise<AccessPoint[]>;
    toggleFavouriteAccessPoint(accessPointGuid: string): Promise<void>;
}
export {};
