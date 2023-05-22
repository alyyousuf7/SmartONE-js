export type ResponseGetRegisterCode = {
  result: string;
  needPrerequirements: boolean;
  communityId: string;
};

export type ResponseRegisterWithCode = {
  buildingId: string;
  suiteId: string;
  communityId: string;
};

export type ResponseGetUser = {
  userId: string;
  username: string;
  email: string | null;
  phone: string | null;
  firstName: string | null;
  lastName: string | null;
  middleName: string | null;
  salutation: string | null;
  notes: string | null;
  isEmailVerified: boolean;
  isPhoneVerified: boolean;
  roles: string | null;
};

export type RequestSmartDeviceServiceLogin = {
  debugYn?: 'Y' | 'N',
  mobileUuid?: string,
  appVersion?: string,
  deviceName?: string,
  osType?: 'iOS' | 'Android',
  osVersion?: string,
  pushTokenId?: string,
  pushToken?: string,
  voipToken?: string,
};

export type ResponseSmartDeviceServiceLogin = {
  accessToken: string;
  refreshToken: string;
  expireIn: number;
  resourceId: string;
  groupId: string;
  userNo: string;
  userId: string;
  huid: string;
  debugYn: 'Y' | 'N';
};

export type ThermostatHVACMode = 'Heat' | 'Cool' | 'Ventilation';
export type ThermostatFanSpeed = 'auto' | 'low' | 'medium' | 'high';
export type ThermostatScene = 'Away' | 'Normal';

export type DeviceThermostat = {
  type: 'Thermostat';
  state: 'on' | 'off';
  id: string;
  name: string;
  category: string;
  serviceName: string;
  manufacture: string;
  mapping: {
    HvacMode: string;
    Scene: string;
    State: string;
    CoolingSetPoint: string;
    HeatingSetPoint: string;
    AwaySetPoint: string;
    FanSpeed: string;
    Temperature: string;
  };

  scale: 'C' | 'F';
  temperature: string;
  coolingSetPoint: number;
  minCoolingSetPoint: number;
  maxCoolingSetPoint: number;
  heatingSetPoint: number;
  minHeatingSetPoint: number;
  maxHeatingSetPoint: number;
  awaySetPoint: number;
  minAwaySetPoint: number;
  maxAwaySetPoint: number;

  hvacMode: string;
  hvacModeOptions: ThermostatHVACMode;
  hvacModeOptions_loc: Array<{
    key: ThermostatHVACMode;
    label: string
  }>;
  hvacModeMapping: {
    [key in ThermostatHVACMode]: string;
  }

  fanSpeed: string;
  fanSpeedOptions: ThermostatFanSpeed[];
  fanSpeedOptions_loc: Array<{
    key: ThermostatFanSpeed;
    label: string
  }>;
  fanSpeedMapping: {
    [key in ThermostatFanSpeed]: string;
  };

  scene: string;
  sceneOptions: ThermostatScene[];
  sceneOptions_loc: Array<{
    key: ThermostatScene;
    label: string
  }>;
  sceneMapping: {
    [key in ThermostatScene]: string;
  };

  status: string;
  stateOptions: any[];
  stateOptions_loc: any[];
};

export type DeviceDetectSensor = {
  type: 'DetectSensors';
  state: string;
  id: string;
  name: string;
  category: string;
  serviceName: string;
  manufacture: string;
  mapping: {
    State: string;
  };
};

export type DeviceDoorLock = {
  type: 'DoorLock';
  state: string;
  id: string;
  name: string;
  category: string;
  serviceName: string;
  manufacture: string;
  mapping: {
    State: string;
  };
};

export type RequestSetDevice = {
  state: 'unlock';
};

export type RequestSetThermostat = {
  heatingSetPoint?: number,
  coolingSetPoint?: number,
  fanSpeed?: 'low' | 'medium' | 'high' | 'auto',
  hvacMode?: 'heat' | 'cool' | 'ventilation',
  scene?: 'Normal' | 'Away',
};

export type ResponseDeviceSet = {
  resultCode: string;
  resultMessage: string;
  commands: {
    cgpCommand: { commandId: string }[];
  };
};

export type ResponseDeviceSetWithMQTT = ResponseDeviceSet & {
  mqtt: {
    expectedMessages: number;
    duration: number;
  };
};

export type Notification = {
  id: string;
  subject: string;
  content: string;
  buildingId: string;
  suites: string[];
  sendTime: string;
};

export type SecurityMode = 'NONE' | 'AWAY' | 'STAY' | 'UNKNOWN';

export type SecuritySwitch = {
  id: string;
  rootId: string;
  name: string;
  commaxDevice: string;
  state: 'on' | 'off';
  type: string;
};

export type CameraChannel = {
  id: number;
  name: string;
  token: string;
  commaxToken: string;
};

export type CameraProxyServer = {
  address: string;
  port: number;
  type: string;
};

export type Camera = {
  id: number;
  bitmask: number;
  channels: CameraChannel[];
  proxyServers: CameraProxyServer[];
  buildingId: string;
};

export type AccessPoint = {
  guid: string;
  name: string;
  alias: string;
  isDefault: boolean;
};
