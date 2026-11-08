# -----------------------------------------------------------------------------
# Predbat Home Battery System
# Copyright Trefor Southwell 2026 - All Rights Reserved
# This application maybe used for personal use only and not for commercial use
# -----------------------------------------------------------------------------
# Hanchu ESS EV charger cloud API library.
# The calls are the ones the Hanchu iESS web console makes for its EV charger
# pages; the sign in is the same one the Hanchu inverter component uses.
# -----------------------------------------------------------------------------
# fmt off
# pylint: disable=consider-using-f-string
# pylint: disable=line-too-long
# pylint: disable=attribute-defined-outside-init


"""Hanchu EV charger integration.

Monitors the Hanchu EV chargers (HC-EV-AC-07K/11K/22K) on a Hanchu iESS account, wires them
into Predbat's car charging inputs, exposes their charging, charging mode, current and
"disable battery discharge to EV charger" controls, and can start and stop each charger from
Predbat's own car charging plan.

The charger calls are the iESS web console's /gateway/platform/evCharger/ family. Unlike the
/gateway/app/ha/ family the inverter component uses, their request bodies are AES-128-CBC
encrypted with a fixed key and IV that every Hanchu client carries, so a small encrypt-only
AES is included here rather than adding a cryptography dependency for one component. These
console calls are not a published API and Hanchu has changed console calls before without
notice, so every failure is reported plainly and stale data is never acted on.
"""

import asyncio
import base64
import json
from dataclasses import dataclass
from typing import Optional

import aiohttp

from component_base import ComponentBase
from car_charger_control import CarChargerControl, ChargerControlDeferred, parse_control_setting
from hanchu_const import HANCHU_BASE_URL, HANCHU_HEADER_LOCALE, HANCHU_HEADER_PLATFORM, HANCHU_HEADER_TOKEN

API_TIMEOUT = 30

LOGIN_PATH = "/gateway/identify/auth/token"
DEVICE_LIST_PATH = "/gateway/app/ha/getDeviceList"
DEVICE_STATUS_PATH = "/gateway/app/ha/getDeviceStatus"
CHARGER_LIST_PATH = "/gateway/platform/evCharger/listEvChargerByStationId"
CHARGER_DETAIL_PATH = "/gateway/platform/evCharger/detail"
CHARGER_READ_PATH = "/gateway/platform/evCharger/realtimeData"
CHARGER_WRITE_PATH = "/gateway/platform/evCharger/remoteControl"

# The fixed key and IV the iESS clients encrypt console request bodies with (the web console and
# the community Home Assistant integrations carry the same value). Obfuscation, not a secret.
HANCHU_AES_KEY = b"9z64Qr8mZH7Pg8d1"
HANCHU_AES_IV = b"9z64Qr8mZH7Pg8d1"

# The DTU (data logger) device type in the app/ha device list; its status names the station
DTU_DEVICE_TYPE = "2"

# ComponentBase.start() calls run() every 60 seconds, so the interval is a whole number of those
MIN_POLL_SECONDS = 60
MAX_POLL_SECONDS = 30 * 60
DEFAULT_POLL_SECONDS = 60
# How often the station and its charger list are read again, to pick up a charger added later
CHARGER_LIST_SECONDS = 30 * 60

MIN_CHARGING_CURRENT = 6
DEFAULT_MAX_CHARGING_CURRENT = 32

HANCHU_EV_STORAGE_MODULE = "hanchu_ev"
HANCHU_EV_CONTROL_STATE = "control_state"

# The settings read from each charger every poll - the app's "Get data"
SETTINGS_KEYS = ("charge_status", "disable_bat_discharge", "charging_mode", "max_current", "work_mode")

# Hanchu's own English labels, from the console's ENUM.CHARGER_WORK_STATUS (OCPP charge point statuses)
CHARGER_WORK_STATUS = {
    0: "Available",
    1: "Preparing",
    2: "Charging",
    3: "SuspendedEV",
    4: "SuspendedEV",
    5: "Finishing",
    6: "Reserved",
    7: "Unavailable",
    8: "Faulted",
}
STATUS_CHARGING = 2
# Statuses Predbat must not command a charger in
STATUS_NOT_READY = (7, 8)

# ENUM.CHARGER_GUN_STATUS: 1 Connecting (a car is on the cable), 2 Disconnected, 3 Charger Failed
GUN_CONNECTED = 1
GUN_DISCONNECTED = 2
GUN_FAILED = 3

# ENUM.CHARGER_CHARG_MODE
CHARGING_MODES = {0: "PV + Battery + Grid", 1: "PV + Battery"}

# The console's ENUM.CHARGER_CHARGING_MODE, the options of the work_mode setting. 4 is the app's "Based on time",
# which charges only inside charge_period (or charge_period_multi), repeated per charge_repeat (0 Daily, 1 Once).
# Hanchu refuses settings changes while a session is open (Charging, SuspendedEVSE, SuspendedEV)
WORK_MODES = {0: "Swipe Charge", 3: "Plug & Charge", 4: "Scheduled charging"}


# -----------------------------------------------------------------------------
# Encrypt-only AES-128-CBC (FIPS-197) with PKCS#7 padding, for console request bodies
# -----------------------------------------------------------------------------
AES_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b27509832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cfd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdbe0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9ee1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16"
)
AES_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


def _xtime(value):
    """Multiply a byte by x in GF(2^8), the AES MixColumns building block."""
    value <<= 1
    return (value ^ 0x11B) if value & 0x100 else value


def aes128_round_keys(key):
    """Expand a 16-byte key into the 11 AES-128 round keys, each 16 bytes."""
    if len(key) != 16:
        raise ValueError("AES-128 needs a 16-byte key")
    words = [list(key[index : index + 4]) for index in range(0, 16, 4)]
    for index in range(4, 44):
        temp = list(words[index - 1])
        if index % 4 == 0:
            temp = temp[1:] + temp[:1]
            temp = [AES_SBOX[byte] for byte in temp]
            temp[0] ^= AES_RCON[index // 4 - 1]
        words.append([words[index - 4][column] ^ temp[column] for column in range(4)])
    return [bytes(sum(words[round_n * 4 : round_n * 4 + 4], [])) for round_n in range(11)]


def aes128_encrypt_block(block, round_keys):
    """Encrypt one 16-byte block with AES-128, given the expanded round keys."""
    state = [byte ^ key_byte for byte, key_byte in zip(block, round_keys[0])]
    for round_n in range(1, 11):
        state = [AES_SBOX[byte] for byte in state]
        # ShiftRows - the state is column major, byte (row, column) at row + 4 * column
        state = [state[((column + row) % 4) * 4 + row] for column in range(4) for row in range(4)]
        if round_n != 10:
            mixed = []
            for column in range(4):
                a0, a1, a2, a3 = state[column * 4 : column * 4 + 4]
                total = a0 ^ a1 ^ a2 ^ a3
                mixed += [a0 ^ total ^ _xtime(a0 ^ a1), a1 ^ total ^ _xtime(a1 ^ a2), a2 ^ total ^ _xtime(a2 ^ a3), a3 ^ total ^ _xtime(a3 ^ a0)]
            state = mixed
        state = [byte ^ key_byte for byte, key_byte in zip(state, round_keys[round_n])]
    return bytes(state)


def aes128_cbc_encrypt(plaintext, key, iv):
    """AES-128-CBC encrypt with PKCS#7 padding."""
    pad = 16 - len(plaintext) % 16
    data = bytes(plaintext) + bytes([pad]) * pad
    round_keys = aes128_round_keys(key)
    previous = bytes(iv)
    out = bytearray()
    for index in range(0, len(data), 16):
        previous = aes128_encrypt_block(bytes(byte ^ chain for byte, chain in zip(data[index : index + 16], previous)), round_keys)
        out += previous
    return bytes(out)


def encrypt_body(data):
    """Encrypt a console request body: compact JSON, AES-128-CBC with the fixed key, then Base64."""
    raw = json.dumps(data, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(aes128_cbc_encrypt(raw, HANCHU_AES_KEY, HANCHU_AES_IV)).decode("ascii")


# -----------------------------------------------------------------------------
# Charger records
# -----------------------------------------------------------------------------
def _to_float(value, default=0.0):
    """Convert to float, returning default for None or junk."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _to_int(value, default=None):
    """Convert to int (via float, for "32.0"), returning default for None or junk."""
    try:
        return int(float(value))
    except (TypeError, ValueError, OverflowError):
        return default


def _current_range(product_config):
    """The charger's current range from its productConfig, e.g. {"max_current": "6-32A"} gives (6, 32)."""
    text = str((product_config or {}).get("max_current") or "").upper().replace("A", "")
    low, _, high = text.partition("-")
    low = _to_int(low, None)
    high = _to_int(high, None)
    if low is None or high is None or low < 1 or high < low:
        return MIN_CHARGING_CURRENT, DEFAULT_MAX_CHARGING_CURRENT
    return low, high


@dataclass
class HanchuEVCharger:
    """One Hanchu EV charger, normalised from its list entry, detail and settings."""

    sn: str
    model: str = ""
    online: bool = False
    status_code: Optional[int] = None
    gun_code: Optional[int] = None
    is_charging: bool = False
    power_w: float = 0.0
    session_energy_kwh: float = 0.0
    voltage: float = 0.0
    current: float = 0.0
    min_current: int = MIN_CHARGING_CURRENT
    max_current_limit: int = DEFAULT_MAX_CHARGING_CURRENT
    phase: str = ""
    firmware: str = ""
    charge_enabled: Optional[bool] = None
    battery_discharge_disabled: Optional[bool] = None
    charging_mode: Optional[int] = None
    max_current: Optional[int] = None
    work_mode: Optional[int] = None
    settings_read: bool = False

    @property
    def status(self):
        """The charger status as Hanchu labels it, or Unknown."""
        return CHARGER_WORK_STATUS.get(self.status_code, "Unknown")

    @property
    def plugged(self):
        """A car is on the cable."""
        return self.gun_code == GUN_CONNECTED

    @property
    def charging(self):
        """The charger reports it is charging."""
        return self.status_code == STATUS_CHARGING

    @property
    def charging_mode_name(self):
        """The charging mode as the app names it, or None when not read."""
        return CHARGING_MODES.get(self.charging_mode)


def normalise_charger(entry, detail=None, settings=None):
    """Build a HanchuEVCharger from a charger list entry, its detail record and its settings.

    The list entry carries the serial, model, status, gun state and online flag; the detail record
    adds the live voltage, current, power (in kW) and session energy; the settings are the app's
    "Get data" values. Any of the last two can be missing - a charger whose detail could not be read
    is still listed - and every value is read defensively, as the console returns most as strings.
    """
    detail = detail or {}
    merged = dict(entry or {})
    merged.update({key: value for key, value in detail.items() if value is not None})
    low, high = _current_range(merged.get("productConfig"))
    charger = HanchuEVCharger(
        sn=str(merged.get("sn") or merged.get("devId") or ""),
        model=str(merged.get("devModelInfo") or ""),
        online=str(merged.get("onlineStatus")) == "1" or merged.get("onLine") is True,
        status_code=_to_int(merged.get("chargerStatus"), None),
        gun_code=_to_int(merged.get("chargerGunStatus"), None),
        is_charging=bool(merged.get("isCharging")),
        power_w=round(_to_float(merged.get("workPwr")) * 1000.0, 1),
        session_energy_kwh=round(_to_float(merged.get("chgCap")), 3),
        voltage=_to_float(merged.get("chgV")),
        current=_to_float(merged.get("chgC")),
        min_current=low,
        max_current_limit=high,
        phase=str(merged.get("phaseType") or (merged.get("productConfig") or {}).get("phase_type") or ""),
        firmware=str(merged.get("controlPanelVer") or ""),
    )
    if settings:
        charge_status = _to_int(settings.get("charge_status"), None)
        disable = _to_int(settings.get("disable_bat_discharge"), None)
        charger.charge_enabled = None if charge_status is None else charge_status == 1
        charger.battery_discharge_disabled = None if disable is None else disable == 1
        charger.charging_mode = _to_int(settings.get("charging_mode"), None)
        charger.max_current = _to_int(settings.get("max_current"), None)
        charger.work_mode = _to_int(settings.get("work_mode"), None)
        charger.settings_read = True
    return charger


# -----------------------------------------------------------------------------
# Transport
# -----------------------------------------------------------------------------
class HanchuEVError(Exception):
    """Any failure talking to the Hanchu cloud."""


class HanchuEVAuthError(HanchuEVError):
    """The sign in was refused - wrong account or password."""


class HanchuEVApiError(HanchuEVError):
    """A call failed: a network error, a bad reply or one reporting failure."""


class HanchuEVRefusedError(HanchuEVApiError):
    """The cloud refused a call this account is not permitted to make."""


class HanchuEVTransport:
    """Sign in to the Hanchu cloud and make the charger calls.

    The token from the sign in is kept until a call is refused as unauthorised, when the transport
    signs in again once and repeats the call. Several clients may be signed in to one account at once.
    """

    def __init__(self, log, account, password, base_url=HANCHU_BASE_URL):
        """Hold the credentials; nothing is sent until the first call."""
        self.log = log
        self.account = account
        self.password = password
        self.base_url = base_url
        self.token = None

    def _headers(self, encrypted):
        """The request headers, with the token once signed in."""
        headers = {"appPlat": HANCHU_HEADER_PLATFORM, "locale": HANCHU_HEADER_LOCALE, "Content-Type": "text/plain" if encrypted else "application/json"}
        if self.token:
            headers[HANCHU_HEADER_TOKEN] = self.token
        return headers

    async def _post(self, path, body, encrypted):
        """POST once and return (HTTP status, decoded JSON or None)."""
        kwargs = {"data": encrypt_body(body)} if encrypted else {"json": body}
        timeout = aiohttp.ClientTimeout(total=API_TIMEOUT)
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.request("POST", self.base_url + path, headers=self._headers(encrypted), **kwargs) as response:
                    status = response.status
                    try:
                        payload = await response.json(content_type=None)
                    except (aiohttp.ContentTypeError, json.JSONDecodeError, ValueError):
                        payload = None
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            raise HanchuEVApiError("{} failed: {}".format(path, exc)) from exc
        return status, payload

    async def authenticate(self):
        """Sign in with the app account, keeping the token."""
        self.token = None
        status, payload = await self._post(LOGIN_PATH, {"account": self.account, "pwd": self.password}, encrypted=False)
        if status == 200 and isinstance(payload, dict) and payload.get("success") and payload.get("data"):
            self.token = payload["data"]
            return
        message = payload.get("msg") if isinstance(payload, dict) else None
        raise HanchuEVAuthError("sign in refused (HTTP {}{})".format(status, ", {}".format(message) if message else ""))

    async def call(self, path, body, encrypted=True):
        """Make a signed-in call and return its data, signing in again once if the token was refused."""
        if not self.token:
            await self.authenticate()
        for attempt in range(2):
            status, payload = await self._post(path, body, encrypted)
            code = payload.get("code") if isinstance(payload, dict) else None
            if status == 401 or code == 401:
                if attempt == 0:
                    await self.authenticate()
                    continue
                raise HanchuEVAuthError("{} unauthorised after signing in again".format(path))
            if status == 403 or code == 403:
                raise HanchuEVRefusedError("{} refused: {}".format(path, payload.get("msg") if isinstance(payload, dict) else "HTTP 403"))
            if status != 200 or not isinstance(payload, dict):
                raise HanchuEVApiError("{} failed: HTTP {}".format(path, status))
            if not payload.get("success", code == 200):
                raise HanchuEVApiError("{} failed: {}".format(path, payload.get("msg") or "code {}".format(code)))
            return payload.get("data")
        raise HanchuEVApiError("{} failed".format(path))  # pragma: no cover - the loop always returns or raises

    async def station_ids(self):
        """The stations on the account, found through each data logger's status."""
        devices = await self.call(DEVICE_LIST_PATH, {}, encrypted=False) or []
        stations = []
        for device in devices:
            if not isinstance(device, dict) or str(device.get("devType")) != DTU_DEVICE_TYPE or not device.get("sn"):
                continue
            status = await self.call(DEVICE_STATUS_PATH, {"sn": device["sn"]}, encrypted=False) or {}
            station = status.get("stationId") if isinstance(status, dict) else None
            if station and station not in stations:
                stations.append(station)
        return stations

    async def list_chargers(self, station_id):
        """The EV chargers on a station, as the console lists them."""
        chargers = await self.call(CHARGER_LIST_PATH, {"stationId": station_id})
        return [charger for charger in (chargers or []) if isinstance(charger, dict) and charger.get("sn")]

    async def get_detail(self, sn):
        """One charger's live detail record."""
        return await self.call(CHARGER_DETAIL_PATH, {"sn": sn}) or {}

    async def read_settings(self, sn, keys=SETTINGS_KEYS):
        """Read settings from the charger itself - the app's "Get data" - as {key: value}."""
        data = await self.call(CHARGER_READ_PATH, {"sn": sn, "protoSems": list(keys)}) or {}
        values = data.get(sn, data) if isinstance(data, dict) else {}
        return values if isinstance(values, dict) else {}

    async def write_settings(self, sn, values):
        """Write settings to one charger, e.g. {"charge_status": 0}."""
        await self.call(CHARGER_WRITE_PATH, {"protoSemMap": dict(values), "sns": [sn]})


# -----------------------------------------------------------------------------
# Component
# -----------------------------------------------------------------------------
hanchu_ev_attribute_table = {
    "status": {"friendly_name": "Hanchu EV Status", "icon": "mdi:information-outline"},
    "power": {"friendly_name": "Hanchu EV Power", "icon": "mdi:lightning-bolt", "unit_of_measurement": "W", "device_class": "power", "state_class": "measurement"},
    "session_energy": {"friendly_name": "Hanchu EV Session Energy", "icon": "mdi:lightning-bolt", "unit_of_measurement": "kWh", "device_class": "energy", "state_class": "total_increasing"},
    "plugged": {"friendly_name": "Hanchu EV Car Plugged In", "icon": "mdi:ev-plug-type2"},
    "charging": {"friendly_name": "Hanchu EV Charging", "icon": "mdi:battery-charging"},
    "charging_switch": {"friendly_name": "Hanchu EV Charge", "icon": "mdi:ev-station"},
    "battery_discharge": {"friendly_name": "Hanchu EV Disable Battery Discharge To Charger", "icon": "mdi:battery-lock"},
    "charging_mode": {"friendly_name": "Hanchu EV Charging Mode", "icon": "mdi:solar-power", "options": list(CHARGING_MODES.values())},
    "max_current": {"friendly_name": "Hanchu EV Maximum Charging Current", "icon": "mdi:current-ac", "unit_of_measurement": "A", "step": 1},
    "control": {"friendly_name": "Hanchu EV Charge Control", "icon": "mdi:ev-station"},
}


class HanchuEVAPI(ComponentBase, CarChargerControl):
    """Hanchu EV charger component: monitoring, controls and Predbat-led charging.

    Predbat-led charging runs on the shared CarChargerControl loop: inside a planned window the
    charger's Charging Status is turned on, outside one it is turned off, and a charger Predbat
    stopped is turned back on when control is released.

    With battery_hold on, each charger's "disable battery discharge to EV charger" setting also
    follows the plan: on inside a car charging window or Octopus Intelligent dispatch, so the car
    charges from the grid while the home battery goes on supplying the house, and off outside one.
    """

    def initialize(self, account, password, automatic=True, hanchu_ev_control=False, poll_seconds=DEFAULT_POLL_SECONDS, chargers=None, battery_hold=False):
        """Set up component state and the transport."""
        self.automatic = automatic
        self.hanchu_ev_control = parse_control_setting(hanchu_ev_control)
        self.charger_control_setup("hanchu_ev", "Hanchu EV charger", HANCHU_EV_STORAGE_MODULE, HANCHU_EV_CONTROL_STATE, "control_enabled", control=self.hanchu_ev_control, switch_prefix="hanchuev", control_setting="hanchu_ev_control")
        self.poll_seconds = min(MAX_POLL_SECONDS, max(MIN_POLL_SECONDS, int(round(_to_float(poll_seconds, DEFAULT_POLL_SECONDS) / 60.0)) * 60))
        if chargers and not isinstance(chargers, list):
            chargers = [chargers]
        # Only these serials, in this order, when set - so one car can be tied to the charger it uses
        self.charger_filter = [str(sn) for sn in chargers] if chargers else None
        self.battery_hold = bool(parse_control_setting(battery_hold))
        self.stations = []
        self.listed = {}
        self.chargers = {}
        self.stale = set()
        self.queued_events = []
        # Serials in car order: entry N is car N. Append-only, so a car never changes number while Predbat runs
        self.car_order = []
        self._auto_configured_order = None
        # Chargers whose Charging Status Predbat itself turned off - one the user turned off is not Predbat's to turn on
        self.stopped_by_predbat = set()
        self.transport = None
        if not account or not password:
            self.log("Error: hanchu_ev: hanchu_ev_account and hanchu_ev_password must both be set")
            return
        self.transport = HanchuEVTransport(self.log, account, password)

    def entity_prefix(self, charger):
        """The entity name prefix for a charger, e.g. predbat_hanchuev_e0102v56m0234."""
        return "{}_hanchuev_{}".format(self.prefix, charger.sn.lower())

    def update_car_order(self, serials):
        """Give every charger a car number, keeping the numbers already handed out.

        With a charger list in apps.yaml its order is the car order and other chargers are not used;
        otherwise chargers are appended in serial order as they are first seen.
        """
        wanted = self.charger_filter if self.charger_filter is not None else sorted(serials)
        for sn in wanted:
            if sn in serials and sn not in self.car_order:
                self.car_order.append(sn)

    def ordered_chargers(self):
        """The chargers that have been read, in car order."""
        return [self.chargers[sn] for sn in self.car_order if sn in self.chargers]

    def automatic_config(self):
        """Wire the charger entities into Predbat's car charging inputs, charger N for car N.

        car_charging_now takes the power sensors (charging from CAR_CHARGING_NOW_POWER_W); a value the
        user set in apps.yaml is kept. car_charging_soc is not set: the charger cannot read the car's
        state of charge.
        """
        if not self.car_order:
            return
        prefixes = ["{}_hanchuev_{}".format(self.prefix, sn.lower()) for sn in self.car_order]
        self.log("Info: hanchu_ev: wiring chargers {} into the car charging inputs".format(self.car_order))
        self.set_arg_auto("car_charging_energy", ["sensor.{}_session_energy".format(prefix) for prefix in prefixes])
        self.set_arg_auto("car_charging_planned", ["binary_sensor.{}_plugged".format(prefix) for prefix in prefixes])
        self.set_arg_auto("car_charging_plugged", ["binary_sensor.{}_plugged".format(prefix) for prefix in prefixes])
        self.set_arg_auto("car_charging_power", ["sensor.{}_power".format(prefix) for prefix in prefixes])
        self.set_arg_auto("car_charging_now", ["sensor.{}_power".format(prefix) for prefix in prefixes], overwrite=False)
        if _to_int(self.get_arg("num_cars", 0), 0) < len(self.car_order):
            self.log("Info: hanchu_ev: setting num_cars to {}".format(len(self.car_order)))
            self.set_arg("num_cars", len(self.car_order))

    async def run(self, seconds, first):
        """Process queued control events, then poll and publish."""
        if not self.transport:
            return False
        if not self.charger_control_loaded:
            await self.charger_control_load_enabled()
        if first:
            self.enable_control()
        try:
            refresh = await self.process_events()
            ok = True
            if first or refresh or (seconds % self.poll_seconds) == 0:
                ok = await self.poll(seconds, first)
            return ok
        except HanchuEVAuthError as exc:
            self.log("Error: hanchu_ev: sign in failed, check hanchu_ev_account and hanchu_ev_password: {}".format(exc))
            return False
        except HanchuEVError as exc:
            self.log("Warn: hanchu_ev: poll failed: {}".format(exc))
            return False

    async def process_events(self):
        """Run every queued control. Returns True when at least one ran, so the caller polls afresh."""
        refresh = False
        while self.queued_events:
            handler, *event_args = self.queued_events.pop(0)
            try:
                await handler(*event_args)
            except HanchuEVAuthError:
                raise
            except Exception as exc:
                # A control the user asked for, so every failure is reported; it is not retried
                self.log("Warn: hanchu_ev: control failed: {}".format(exc))
            refresh = True
        return refresh

    async def poll(self, seconds, first):
        """Read every charger, publish, wire the car inputs, and run charge control and battery hold."""
        if first or not self.listed or (seconds % CHARGER_LIST_SECONDS) == 0:
            if first or not self.stations:
                self.stations = await self.transport.station_ids()
            listed = {}
            for station in self.stations:
                for entry in await self.transport.list_chargers(station):
                    listed[str(entry["sn"])] = entry
            self.listed = listed
            self.update_car_order(list(listed))
        if not self.listed:
            if first:
                self.log("Warn: hanchu_ev: signed in but no EV chargers were found on the account")
            return True

        chargers = {}
        stale = set()
        for sn in self.car_order:
            try:
                detail = await self.transport.get_detail(sn)
                settings = await self.transport.read_settings(sn)
                chargers[sn] = normalise_charger(self.listed.get(sn), detail, settings)
            except HanchuEVAuthError:
                raise
            except HanchuEVError as exc:
                self.log("Warn: hanchu_ev: could not read charger {}: {}".format(sn, exc))
                # Kept, so the charger keeps its place, but marked stale so nothing acts on old state
                if sn in self.chargers:
                    chargers[sn] = self.chargers[sn]
                    stale.add(sn)
        if self.car_order and len(stale) == len(chargers):
            raise HanchuEVApiError("no charger could be read")
        self.chargers = chargers
        self.stale = stale
        await self.publish_data()
        if self.automatic and self._auto_configured_order != self.car_order:
            self.automatic_config()
            self._auto_configured_order = list(self.car_order)
        now = self.now_utc_exact
        await self.control_tick(now)
        await self.battery_hold_tick(now)
        self.update_success_timestamp()
        return True

    async def publish_data(self):
        """Publish every known charger as Predbat entities."""
        if self.charger_control_active:
            self.dashboard_item("switch.{}_hanchuev_control".format(self.prefix), state="on" if self.charger_control_enabled else "off", attributes=hanchu_ev_attribute_table["control"], app="hanchu_ev")
            self.charger_control_publish_guest("hanchu_ev")
        for charger in self.ordered_chargers():
            prefix = self.entity_prefix(charger)
            status_attributes = dict(hanchu_ev_attribute_table["status"])
            status_attributes.update(
                {
                    "status_code": charger.status_code,
                    "gun_status": charger.gun_code,
                    "online": charger.online,
                    "serial_number": charger.sn,
                    "model": charger.model,
                    "firmware": charger.firmware,
                    "phase": charger.phase,
                    "voltage": charger.voltage,
                    "current": charger.current,
                    "work_mode": WORK_MODES.get(charger.work_mode, charger.work_mode),
                    "stale": charger.sn in self.stale,
                }
            )
            current_attributes = dict(hanchu_ev_attribute_table["max_current"])
            current_attributes.update({"min": charger.min_current, "max": charger.max_current_limit})
            self.dashboard_item("sensor.{}_status".format(prefix), state=charger.status, attributes=status_attributes, app="hanchu_ev")
            self.dashboard_item("sensor.{}_power".format(prefix), state=charger.power_w, attributes=hanchu_ev_attribute_table["power"], app="hanchu_ev")
            self.dashboard_item("sensor.{}_session_energy".format(prefix), state=charger.session_energy_kwh, attributes=hanchu_ev_attribute_table["session_energy"], app="hanchu_ev")
            self.dashboard_item("binary_sensor.{}_plugged".format(prefix), state=plugged_state(charger), attributes=hanchu_ev_attribute_table["plugged"], app="hanchu_ev")
            self.dashboard_item("binary_sensor.{}_charging".format(prefix), state="on" if charger.charging else "off", attributes=hanchu_ev_attribute_table["charging"], app="hanchu_ev")
            if charger.settings_read:
                self.dashboard_item("switch.{}_charging".format(prefix), state="on" if charger.charge_enabled else "off", attributes=hanchu_ev_attribute_table["charging_switch"], app="hanchu_ev")
                self.dashboard_item("switch.{}_disable_battery_discharge".format(prefix), state="on" if charger.battery_discharge_disabled else "off", attributes=hanchu_ev_attribute_table["battery_discharge"], app="hanchu_ev")
                if charger.charging_mode_name is not None:
                    self.dashboard_item("select.{}_charging_mode".format(prefix), state=charger.charging_mode_name, attributes=hanchu_ev_attribute_table["charging_mode"], app="hanchu_ev")
                if charger.max_current is not None:
                    self.dashboard_item("number.{}_max_current".format(prefix), state=charger.max_current, attributes=current_attributes, app="hanchu_ev")

    def charger_for_entity(self, entity_id):
        """Find the charger an entity belongs to, or None. The trailing underscore anchors the match."""
        for charger in self.chargers.values():
            if "{}_".format(self.entity_prefix(charger)) in entity_id:
                return charger
        return None

    async def switch_event(self, entity_id, service):
        """Queue a switch service call for the run loop."""
        self.queued_events.append((self.switch_event_handler, entity_id, service))

    async def number_event(self, entity_id, value):
        """Queue a number change for the run loop."""
        self.queued_events.append((self.number_event_handler, entity_id, value))

    async def select_event(self, entity_id, value):
        """Queue a select change for the run loop."""
        self.queued_events.append((self.select_event_handler, entity_id, value))

    async def switch_event_handler(self, entity_id, service):
        """Charging Status, battery discharge, the control switch and guest charging."""
        if await self.charger_control_guest_event(entity_id, service):
            return
        if service not in ("turn_on", "turn_off"):
            return
        turn_on = service == "turn_on"
        if entity_id.endswith("_hanchuev_control"):
            await self.charger_control_set_enabled(turn_on)
            return
        charger = self.charger_for_entity(entity_id)
        if not charger:
            return
        if entity_id.endswith("_disable_battery_discharge"):
            self.log("Info: hanchu_ev: {} battery discharge to charger {}".format("disabling" if turn_on else "allowing", charger.sn))
            await self.transport.write_settings(charger.sn, {"disable_bat_discharge": 1 if turn_on else 0})
        elif entity_id.endswith("_charging"):
            self.log("Info: hanchu_ev: turning charger {} Charging Status {}".format(charger.sn, "on" if turn_on else "off"))
            await self.transport.write_settings(charger.sn, {"charge_status": 1 if turn_on else 0})

    async def number_event_handler(self, entity_id, value):
        """Set the maximum charging current, clamped to the charger's range."""
        if not entity_id.endswith("_max_current"):
            return
        charger = self.charger_for_entity(entity_id)
        if not charger:
            return
        amps = _to_int(value, None)
        if amps is None:
            self.log("Warn: hanchu_ev: ignoring charging current '{}' for charger {}".format(value, charger.sn))
            return
        amps = max(charger.min_current, min(charger.max_current_limit, amps))
        self.log("Info: hanchu_ev: setting charger {} maximum charging current to {}A".format(charger.sn, amps))
        await self.transport.write_settings(charger.sn, {"max_current": amps})

    async def select_event_handler(self, entity_id, value):
        """Set the charging mode - which sources may supply the charger."""
        if not entity_id.endswith("_charging_mode"):
            return
        charger = self.charger_for_entity(entity_id)
        mode = next((code for code, name in CHARGING_MODES.items() if name == value), None)
        if not charger or mode is None:
            return
        self.log("Info: hanchu_ev: setting charger {} charging mode to {}".format(charger.sn, value))
        await self.transport.write_settings(charger.sn, {"charging_mode": mode})

    def enable_control(self):
        """Decide whether Predbat-led charging can run, and say why when it cannot."""
        self.charger_control_active = False
        if not self.hanchu_ev_control:
            return
        if not self.automatic:
            self.log("Warn: hanchu_ev: hanchu_ev_control needs hanchu_ev_automatic to map each charger to a car, charge control is disabled")
            return
        self.charger_control_active = True
        self.log("Info: hanchu_ev: Predbat-led charge control enabled")

    async def control_tick(self, now):
        """Run one cycle of the shared charge control, reporting a failed command rather than failing the poll."""
        try:
            await self.charger_control_tick(now)
        except HanchuEVAuthError:
            raise
        except HanchuEVError as exc:
            self.log("Warn: hanchu_ev: charge control failed: {}".format(exc))

    async def battery_hold_tick(self, now):
        """With battery_hold on, keep each charger's battery discharge setting in step with the plan.

        On inside a car charging window or an Octopus Intelligent dispatch, off outside one. Written
        only when the charger reports something different, never to a charger that could not be read,
        and never in read only mode.
        """
        if not self.battery_hold or self.charger_control_read_only_now():
            return
        if not self.charger_control_refresh_windows(now):
            return
        for car_n, charger in enumerate(self.ordered_chargers()[: self.charger_control_car_count()]):
            if charger.sn in self.stale or not charger.settings_read or not charger.online:
                continue
            hold = bool(self.charger_control_should_charge(car_n, now))
            if charger.battery_discharge_disabled == hold:
                continue
            self.log("Info: hanchu_ev: {} battery discharge to charger {} for car {}".format("disabling" if hold else "allowing", charger.sn, car_n))
            try:
                await self.transport.write_settings(charger.sn, {"disable_bat_discharge": 1 if hold else 0})
                charger.battery_discharge_disabled = hold
            except HanchuEVAuthError:
                raise
            except HanchuEVError as exc:
                self.log("Warn: hanchu_ev: could not set battery discharge on charger {}: {}".format(charger.sn, exc))

    # An account-wide refusal stops the control loop at once, see CarChargerControl.charger_control_each()
    charger_control_fatal_errors = (HanchuEVAuthError,)

    def charger_control_extra_state(self):
        """Save which chargers Predbat turned off alongside the shared control state."""
        return {"stopped": sorted(self.stopped_by_predbat)}

    def charger_control_restore_extra(self, saved):
        """Restore which chargers Predbat turned off."""
        stopped = saved.get("stopped")
        if isinstance(stopped, list):
            self.stopped_by_predbat.update(str(sn) for sn in stopped)

    def charger_control_chargers(self):
        """The chargers that have been read, in car order, so charger N follows car N."""
        return [(charger.sn, charger) for charger in self.ordered_chargers()]

    def charger_control_car_count(self):
        """One car per charger in the car order."""
        return len(self.car_order)

    def charger_control_unplugged(self, charger):
        """Does a freshly read charger positively say there is no car."""
        return charger.sn not in self.stale and charger.gun_code == GUN_DISCONNECTED

    def charger_control_car_plugged(self, charger):
        """Is a car plugged in, for ending guest charging - anything but a positive disconnect reads as plugged in."""
        return charger.gun_code != GUN_DISCONNECTED

    def charger_control_connected(self, charger):
        """Can Predbat act on this charger now: freshly read with its settings, online, a car on the cable, not faulted."""
        if charger.sn in self.stale or not charger.settings_read or not charger.online:
            return False
        return charger.plugged and charger.status_code not in STATUS_NOT_READY

    def charger_control_drifted(self, charger, charge):
        """Has the charger's Charging Status been changed away from what Predbat set - e.g. from the Hanchu app."""
        return charger.charge_enabled is not None and charger.charge_enabled != charge

    async def charger_control_send(self, charger, charge, car_n):
        """Turn Charging Status on inside a window, off outside one - only when the charger is not already there.

        In Swipe Charge mode, the recommended set-up, a charger with a car plugged in rests with its Charging Status
        off and never starts by itself, so outside a window there is usually nothing to stop. Hanchu refuses a stop
        to a charger with no session, so sending one would only fail every cycle. A charger already off is not
        recorded as stopped by Predbat, so a release does not start it either.
        """
        if charger.charge_enabled is charge:
            return
        if charge:
            self.log("Info: hanchu_ev: turning charger {} on for car {}".format(charger.sn, car_n))
            await self.transport.write_settings(charger.sn, {"charge_status": 1})
            charger.charge_enabled = True
            if charger.sn in self.stopped_by_predbat:
                self.stopped_by_predbat.discard(charger.sn)
                await self.charger_control_save()
        else:
            self.log("Info: hanchu_ev: turning charger {} off for car {}".format(charger.sn, car_n))
            # Recorded and stored before it is sent: a stop whose reply is lost may still have been applied
            if charger.sn not in self.stopped_by_predbat:
                self.stopped_by_predbat.add(charger.sn)
                await self.charger_control_save()
            await self.transport.write_settings(charger.sn, {"charge_status": 0})
            charger.charge_enabled = False

    async def charger_control_release_one(self, charger, charge):
        """Release one charger: turn Charging Status back on if Predbat turned it off.

        A charger the user turned off stays off. One that cannot be read now is deferred to the next
        poll; one with no car owes nothing.
        """
        if charger.sn in self.stale or not charger.online:
            raise ChargerControlDeferred()
        if charger.sn not in self.stopped_by_predbat:
            return
        if charger.gun_code == GUN_DISCONNECTED:
            self.stopped_by_predbat.discard(charger.sn)
            await self.charger_control_save()
            return
        if charger.charge_enabled is False:
            self.log("Info: hanchu_ev: releasing charger {}".format(charger.sn))
            await self.transport.write_settings(charger.sn, {"charge_status": 1})
            charger.charge_enabled = True
        self.stopped_by_predbat.discard(charger.sn)
        await self.charger_control_save()


def plugged_state(charger):
    """binary_sensor.<prefix>_plugged: on with a car on the cable, off when the charger says there is none, else unavailable."""
    if charger.gun_code == GUN_CONNECTED:
        return "on"
    if charger.gun_code == GUN_DISCONNECTED:
        return "off"
    return "unavailable"
