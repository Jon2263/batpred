# fmt: off
# pylint: disable=line-too-long
"""
Unit tests for the Hanchu EV charger integration
"""

import datetime
import os
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytz

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.test_infra import run_async
from mock_base import MockBase

from hanchu_ev import (
    CHARGER_LIST_PATH,
    CHARGER_READ_PATH,
    CHARGER_WRITE_PATH,
    DEVICE_LIST_PATH,
    DEVICE_STATUS_PATH,
    LOGIN_PATH,
    MAX_POLL_SECONDS,
    MIN_POLL_SECONDS,
    HanchuEVAPI,
    HanchuEVApiError,
    HanchuEVAuthError,
    HanchuEVRefusedError,
    HanchuEVTransport,
    aes128_encrypt_block,
    aes128_round_keys,
    encrypt_body,
    normalise_charger,
    plugged_state,
)

SN_A = "E0102V56M0234"
SN_B = "E010YM56M0439"


def _response(json_data=None, status=200, json_error=None):
    """Build a mock aiohttp response usable as an async context manager."""
    response = MagicMock()
    response.status = status
    if json_error is not None:
        response.json = AsyncMock(side_effect=json_error)
    else:
        response.json = AsyncMock(return_value=json_data)
    response.__aenter__ = AsyncMock(return_value=response)
    response.__aexit__ = AsyncMock(return_value=False)
    return response


def _session(responses):
    """Build a mock aiohttp session returning queued responses; records every request."""
    calls = []
    queue = list(responses)

    def _request(method, url, **kwargs):
        """Record the request, then return or raise the next queued item."""
        calls.append({"method": method, "url": url, "headers": kwargs.get("headers") or {}, "json": kwargs.get("json"), "data": kwargs.get("data")})
        item = queue.pop(0) if queue else _response({"success": True, "code": 200, "data": None})
        if isinstance(item, BaseException):
            raise item
        return item

    session = MagicMock()
    session.request = _request
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=False)
    return session, calls


def _ok(data):
    """A successful Hanchu reply."""
    return _response({"code": 200, "success": True, "data": data})


def _transport():
    """A transport with a captured log."""
    return HanchuEVTransport(lambda message: None, "user@example.com", "secret")


# -----------------------------------------------------------------------------
# Encryption
# -----------------------------------------------------------------------------
def test_aes_fips197_vector():
    """The AES-128 block cipher matches the FIPS-197 Appendix C.1 example."""
    round_keys = aes128_round_keys(bytes(range(16)))
    assert aes128_encrypt_block(bytes.fromhex("00112233445566778899aabbccddeeff"), round_keys).hex() == "69c4e0d86a7b0430d8cdb78070b4c55a"
    try:
        aes128_round_keys(b"short")
        assert False, "a bad key length must be refused"
    except ValueError:
        pass
    print("  ✓ AES-128 matches FIPS-197")


def test_encrypt_body_matches_reference():
    """Console bodies encrypt exactly as a reference AES-CBC/PKCS#7 implementation does with the iESS key."""
    # cspell:disable-next-line
    assert encrypt_body({}) == "7z3KJy238sQCI6D33JIbyg=="
    assert encrypt_body({"protoSemMap": {"charge_status": 1}, "sns": ["E000TEST0001"]}) == "C6mRR+MYDdllSNZhFmOs2bzd3BAesSimdNLeFlXfjN3xWbXCgapHjQtvlaLidIgukwMAczR9KbF+xkyO117mwg=="
    assert (
        encrypt_body({"sn": "E000TEST0001", "protoSems": ["charge_status", "disable_bat_discharge"]})
        == "wCylETUrETQGAMHWXOAZni9vUaz/ili7hS0t/8iNSPjmHVa3d3hCC+/Bqybu5N9tJy6JqUJQabAQTaBM1Qicn4UFozrzS4phOTNo9EEBObk="
    )
    print("  ✓ Request bodies encrypt to the reference values")


# -----------------------------------------------------------------------------
# Charger records
# -----------------------------------------------------------------------------
def _entry(sn=SN_A, status="2", gun="1", online=1):
    """A charger list entry in the console's shape."""
    return {"sn": sn, "devId": sn, "chargerStatus": status, "chargerGunStatus": gun, "onlineStatus": online, "devModelInfo": "HC-EV-AC-07K-S1", "workMode": "3", "config": "{}", "onLine": bool(online)}


def _detail(sn=SN_A, status="2", gun="1", power="7.06", energy="12.5"):
    """A charger detail record in the console's shape, values as strings."""
    return {
        "sn": sn, "chargerStatus": status, "chargerGunStatus": gun, "onlineStatus": "1", "isCharging": status == "2",
        "chgV": "239.1", "chgC": "29.5", "workPwr": power, "chgCap": energy, "controlPanelVer": "V1.01.56", "phaseType": "single",
        "productConfig": {"max_current": "6-32A", "phase_type": "single"},
    }


def _settings(charge="1", hold="0", mode="0", current="32", work="3"):
    """The app's "Get data" values for a charger, as strings."""
    return {"charge_status": charge, "disable_bat_discharge": hold, "charging_mode": mode, "max_current": current, "work_mode": work}


def test_normalise_charging():
    """A charging charger is read from its list entry, detail and settings."""
    charger = normalise_charger(_entry(), _detail(), _settings())
    assert charger.sn == SN_A and charger.model == "HC-EV-AC-07K-S1" and charger.online
    assert charger.status == "Charging" and charger.charging and charger.plugged
    assert charger.power_w == 7060.0 and charger.session_energy_kwh == 12.5
    assert charger.voltage == 239.1 and charger.current == 29.5
    assert (charger.min_current, charger.max_current_limit) == (6, 32)
    assert charger.charge_enabled is True and charger.battery_discharge_disabled is False
    assert charger.charging_mode_name == "PV + Battery + Grid" and charger.max_current == 32 and charger.work_mode == 3
    assert charger.settings_read
    print("  ✓ A charging charger is normalised")


def test_normalise_handles_missing_and_junk():
    """No detail or settings, and junk values, read as safe defaults rather than raising."""
    charger = normalise_charger(_entry(status="junk", gun=None, online=0))
    assert charger.status == "Unknown" and not charger.online and not charger.plugged and not charger.settings_read
    assert charger.charge_enabled is None and charger.charging_mode_name is None
    junk = normalise_charger(_entry(), {"workPwr": "n/a", "chgCap": None, "productConfig": {"max_current": "fast"}}, {"charge_status": "?", "max_current": "x"})
    assert junk.power_w == 0.0 and junk.session_energy_kwh == 0.0
    assert (junk.min_current, junk.max_current_limit) == (6, 32)
    assert junk.charge_enabled is None and junk.max_current is None and junk.settings_read
    suspended = normalise_charger(_entry(status="4"), _detail(status="4", power="0.00"), _settings(hold="1", mode="1"))
    assert suspended.status == "SuspendedEV" and not suspended.charging and suspended.battery_discharge_disabled
    assert suspended.charging_mode_name == "PV + Battery"
    print("  ✓ Missing and junk values are handled")


def test_plugged_state():
    """The plugged sensor is on, off, or unavailable when the gun state is not known."""
    assert plugged_state(normalise_charger(_entry(gun="1"))) == "on"
    assert plugged_state(normalise_charger(_entry(gun="2"))) == "off"
    assert plugged_state(normalise_charger(_entry(gun="3"))) == "unavailable"
    print("  ✓ Plugged state")


# -----------------------------------------------------------------------------
# Transport
# -----------------------------------------------------------------------------
def test_transport_signs_in_then_calls_encrypted():
    """The sign in is plain JSON; console calls carry the token and an encrypted text body."""
    session, calls = _session([_ok("token-1"), _ok({SN_A: _settings()})])
    transport = _transport()
    with patch("hanchu_ev.aiohttp.ClientSession", return_value=session):
        values = run_async(transport.read_settings(SN_A))
    assert values["charge_status"] == "1"
    assert calls[0]["url"].endswith(LOGIN_PATH) and calls[0]["json"] == {"account": "user@example.com", "pwd": "secret"}
    assert calls[0]["headers"]["appPlat"] == "ha"
    assert calls[1]["url"].endswith(CHARGER_READ_PATH) and calls[1]["json"] is None
    assert calls[1]["data"] == encrypt_body({"sn": SN_A, "protoSems": ["charge_status", "disable_bat_discharge", "charging_mode", "max_current", "work_mode"]})
    assert calls[1]["headers"]["access-token"] == "token-1" and calls[1]["headers"]["Content-Type"] == "text/plain"
    print("  ✓ Signs in, then sends encrypted console calls with the token")


def test_transport_signs_in_again_once_on_401():
    """A refused token is replaced by signing in again, once."""
    session, calls = _session([_ok("token-1"), _response({"code": 401, "msg": "Auth Failed!"}, status=401), _ok("token-2"), _ok(None)])
    transport = _transport()
    with patch("hanchu_ev.aiohttp.ClientSession", return_value=session):
        run_async(transport.write_settings(SN_A, {"charge_status": 0}))
    assert [call["url"].split("/gateway")[1] for call in calls] == [LOGIN_PATH[8:], CHARGER_WRITE_PATH[8:], LOGIN_PATH[8:], CHARGER_WRITE_PATH[8:]]
    assert calls[3]["headers"]["access-token"] == "token-2"
    assert calls[3]["data"] == encrypt_body({"protoSemMap": {"charge_status": 0}, "sns": [SN_A]})

    session, _ = _session([_ok("token-1"), _response({"code": 401}, status=401), _ok("token-2"), _response({"code": 401}, status=401)])
    with patch("hanchu_ev.aiohttp.ClientSession", return_value=session):
        try:
            run_async(_transport().get_detail(SN_A))
            assert False, "a second 401 must raise"
        except HanchuEVAuthError:
            pass
    print("  ✓ Signs in again once after a refused token")


def test_transport_bad_credentials():
    """A refused sign in raises an auth error with Hanchu's message."""
    session, _ = _session([_response({"code": 90076, "success": False, "msg": "Account or password incorrect"})])
    with patch("hanchu_ev.aiohttp.ClientSession", return_value=session):
        try:
            run_async(_transport().authenticate())
            assert False, "bad credentials must raise"
        except HanchuEVAuthError as exc:
            assert "Account or password incorrect" in str(exc)
    print("  ✓ Bad credentials are reported")


def test_transport_failures():
    """Permission refusals, failed replies, bad HTTP and network errors are all reported."""
    cases = [
        (_response({"code": 403, "msg": "Permission Denied"}, status=403), HanchuEVRefusedError),
        (_response({"code": 500, "success": False, "msg": "busy"}), HanchuEVApiError),
        (_response(None, status=502, json_error=ValueError("not json")), HanchuEVApiError),
        (aiohttp.ClientError("down"), HanchuEVApiError),
    ]
    for reply, error in cases:
        session, _ = _session([_ok("token-1"), reply])
        with patch("hanchu_ev.aiohttp.ClientSession", return_value=session):
            try:
                run_async(_transport().get_detail(SN_A))
                assert False, "expected {}".format(error.__name__)
            except error:
                pass
    print("  ✓ Failures raise the right errors")


def test_transport_finds_stations_and_chargers():
    """Stations come from each data logger's status; the charger list skips entries without a serial."""
    session, calls = _session([
        _ok("token-1"),
        _ok([{"devType": "2", "sn": "H01"}, {"devType": "1", "sn": "BAT"}, {"devType": "2", "sn": "H02"}]),
        _ok({"stationId": "ST1"}),
        _ok({"stationId": "ST1"}),
        _ok([_entry(), {"noSerial": True}]),
    ])
    transport = _transport()
    with patch("hanchu_ev.aiohttp.ClientSession", return_value=session):
        assert run_async(transport.station_ids()) == ["ST1"]
        chargers = run_async(transport.list_chargers("ST1"))
    assert [charger["sn"] for charger in chargers] == [SN_A]
    assert calls[1]["url"].endswith(DEVICE_LIST_PATH) and calls[2]["url"].endswith(DEVICE_STATUS_PATH) and calls[2]["json"] == {"sn": "H01"}
    assert calls[4]["url"].endswith(CHARGER_LIST_PATH) and calls[4]["data"] == encrypt_body({"stationId": "ST1"})
    print("  ✓ Stations and chargers are found")


# -----------------------------------------------------------------------------
# Component
# -----------------------------------------------------------------------------
class _StubTransport:
    """In-memory transport: serves chargers by serial and records every write."""

    def __init__(self, chargers=None):
        """chargers maps serial to (entry, detail, settings)."""
        self.chargers = chargers if chargers is not None else {SN_A: (_entry(), _detail(), _settings())}
        self.writes = []
        self.errors = {}

    def _maybe_fail(self, name, sn=None):
        """Raise the error queued for this call, once."""
        error = self.errors.pop((name, sn), None) or self.errors.pop((name,), None)
        if error:
            raise error

    async def station_ids(self):
        """One station."""
        self._maybe_fail("station_ids")
        return ["ST1"]

    async def list_chargers(self, station_id):
        """The list entries held."""
        self._maybe_fail("list_chargers")
        return [entry for entry, _, _ in self.chargers.values()]

    async def get_detail(self, sn):
        """One charger's detail."""
        self._maybe_fail("get_detail", sn)
        return self.chargers[sn][1]

    async def read_settings(self, sn, keys=None):
        """One charger's settings."""
        self._maybe_fail("read_settings", sn)
        return self.chargers[sn][2]

    async def write_settings(self, sn, values):
        """Record a write and apply it to the settings served next."""
        self._maybe_fail("write_settings", sn)
        self.writes.append((sn, dict(values)))
        self.chargers[sn][2].update({key: str(value) for key, value in values.items()})


def _make_component(served=None, **overrides):
    """Build a HanchuEVAPI against MockBase with a stub transport and a captured log."""
    args = {"account": "user@example.com", "password": "secret", "automatic": True, "hanchu_ev_control": False, "poll_seconds": 60}
    args.update(overrides)
    component = HanchuEVAPI(MockBase(), **args)
    component.transport = _StubTransport(served)
    component.log_messages = []
    component.log = component.log_messages.append
    return component


def _logged(component, text):
    """Was a message containing this text logged."""
    return any(text in message for message in component.log_messages)


def test_component_registration():
    """The component is registered with matching config keys, schema entries and its own event filter."""
    import inspect

    from components import COMPONENT_LIST, load_component_class
    from config import APPS_SCHEMA

    entry = COMPONENT_LIST["hanchu_ev"]
    assert load_component_class(entry) is HanchuEVAPI
    assert entry["event_filter"] == "predbat_hanchuev_"
    assert not entry["event_filter"].startswith(COMPONENT_LIST["hanchu"]["event_filter"]), "must not share the inverter component's events"
    assert entry["args"]["account"]["required"] is True and entry["args"]["account"]["secret"] is True
    assert entry["args"]["password"]["required"] is True and entry["args"]["password"]["secret"] is True
    parameters = inspect.signature(HanchuEVAPI.initialize).parameters
    for arg_name, spec in entry["args"].items():
        assert arg_name in parameters, "initialize() has no parameter '{}'".format(arg_name)
        assert spec["config"] in APPS_SCHEMA, "{} missing from APPS_SCHEMA".format(spec["config"])
    print("  ✓ Component is registered with matching config keys")


def test_component_settings():
    """Missing credentials disable it; the poll interval is clamped to whole minutes; a single charger filter becomes a list."""
    component = HanchuEVAPI(MockBase(), account=None, password="secret")
    assert component.transport is None and run_async(component.run(0, True)) is False
    assert _make_component(poll_seconds=90).poll_seconds == 120
    assert _make_component(poll_seconds=5).poll_seconds == MIN_POLL_SECONDS
    assert _make_component(poll_seconds=99999).poll_seconds == MAX_POLL_SECONDS
    assert _make_component(poll_seconds="junk").poll_seconds == 60
    assert _make_component(chargers=SN_A).charger_filter == [SN_A]
    print("  ✓ Settings are validated")


def test_component_publishes_one_charger():
    """One charger publishes exactly the expected entities and values."""
    component = _make_component()
    assert run_async(component.run(0, True)) is True
    entities = component.base.entities
    prefix = "predbat_hanchuev_{}".format(SN_A.lower())
    published = {name for name in entities if "_hanchuev_" in name}
    assert published == {
        "sensor.{}_status".format(prefix), "sensor.{}_power".format(prefix), "sensor.{}_session_energy".format(prefix),
        "binary_sensor.{}_plugged".format(prefix), "binary_sensor.{}_charging".format(prefix),
        "switch.{}_charging".format(prefix), "switch.{}_disable_battery_discharge".format(prefix),
        "select.{}_charging_mode".format(prefix), "number.{}_max_current".format(prefix),
    }, published
    assert entities["sensor.{}_status".format(prefix)]["state"] == "Charging"
    assert entities["sensor.{}_status".format(prefix)]["attributes"]["serial_number"] == SN_A
    assert entities["sensor.{}_power".format(prefix)]["state"] == 7060.0
    assert entities["sensor.{}_session_energy".format(prefix)]["state"] == 12.5
    assert entities["binary_sensor.{}_plugged".format(prefix)]["state"] == "on"
    assert entities["switch.{}_charging".format(prefix)]["state"] == "on"
    assert entities["switch.{}_disable_battery_discharge".format(prefix)]["state"] == "off"
    assert entities["select.{}_charging_mode".format(prefix)]["state"] == "PV + Battery + Grid"
    number = entities["number.{}_max_current".format(prefix)]
    assert number["state"] == 32 and number["attributes"]["min"] == 6 and number["attributes"]["max"] == 32
    assert component.last_success_timestamp is not None
    print("  ✓ One charger publishes the expected entities")


def test_component_automatic_config_and_filter():
    """Chargers are wired into the car inputs in serial order, or only those listed, in that order."""
    two = {SN_B: (_entry(SN_B, status="0", gun="2"), _detail(SN_B, status="0", gun="2", power="0"), _settings(charge="0")), SN_A: (_entry(), _detail(), _settings())}
    component = _make_component(two)
    run_async(component.run(0, True))
    args = component.base.args
    assert component.car_order == [SN_A, SN_B]
    assert args["car_charging_energy"] == ["sensor.predbat_hanchuev_{}_session_energy".format(sn.lower()) for sn in (SN_A, SN_B)]
    assert args["car_charging_power"] == ["sensor.predbat_hanchuev_{}_power".format(sn.lower()) for sn in (SN_A, SN_B)]
    assert args["car_charging_plugged"] == ["binary_sensor.predbat_hanchuev_{}_plugged".format(sn.lower()) for sn in (SN_A, SN_B)]
    assert args["num_cars"] == 2

    only_b = _make_component({key: (dict(value[0]), dict(value[1]), dict(value[2])) for key, value in two.items()}, chargers=[SN_B])
    run_async(only_b.run(0, True))
    assert only_b.car_order == [SN_B] and only_b.base.args["num_cars"] == 1
    assert not any(SN_A.lower() in name for name in only_b.base.entities)
    print("  ✓ Automatic configuration and the charger list")


def test_controls_are_queued_then_written():
    """Each control is queued and then written to the charger as the console expects."""
    component = _make_component()
    run_async(component.run(0, True))
    prefix = "switch.predbat_hanchuev_{}".format(SN_A.lower())
    run_async(component.switch_event(prefix + "_disable_battery_discharge", "turn_on"))
    run_async(component.switch_event(prefix + "_charging", "turn_off"))
    run_async(component.select_event("select.predbat_hanchuev_{}_charging_mode".format(SN_A.lower()), "PV + Battery"))
    run_async(component.number_event("number.predbat_hanchuev_{}_max_current".format(SN_A.lower()), "40"))
    run_async(component.number_event("number.predbat_hanchuev_{}_max_current".format(SN_A.lower()), "junk"))
    run_async(component.select_event("select.predbat_hanchuev_{}_charging_mode".format(SN_A.lower()), "Nonsense"))
    assert component.transport.writes == []
    run_async(component.run(60, False))
    assert component.transport.writes == [
        (SN_A, {"disable_bat_discharge": 1}),
        (SN_A, {"charge_status": 0}),
        (SN_A, {"charging_mode": 1}),
        (SN_A, {"max_current": 32}),
    ], component.transport.writes
    assert _logged(component, "ignoring charging current 'junk'")
    entities = component.base.entities
    assert entities[prefix + "_disable_battery_discharge"]["state"] == "on" and entities[prefix + "_charging"]["state"] == "off"
    print("  ✓ Controls are queued and written")


def test_failed_reads_mark_stale_and_auth_failure():
    """One charger failing keeps its last record marked stale; every charger failing fails the cycle; a refused sign in is an error."""
    component = _make_component()
    run_async(component.run(0, True))
    component.transport.errors[("get_detail", SN_A)] = HanchuEVApiError("busy")
    assert run_async(component.run(60, False)) is False
    assert _logged(component, "could not read charger")

    component = _make_component()
    component.transport.errors[("station_ids",)] = HanchuEVAuthError("bad password")
    assert run_async(component.run(0, True)) is False
    assert _logged(component, "sign in failed")
    print("  ✓ Read failures and sign in failures")


CONTROL_TZ = pytz.timezone("Europe/London")
CONTROL_NOW = CONTROL_TZ.localize(datetime.datetime(2026, 11, 8, 23, 30))


def _plan_window(start, end):
    """One planned-window dict in the shape output.py publishes."""
    return {"start": start.strftime("%m-%d %H:%M:%S"), "end": end.strftime("%m-%d %H:%M:%S")}


PLAN_INSIDE = [_plan_window(datetime.datetime(2026, 11, 8, 23, 0), datetime.datetime(2026, 11, 9, 1, 0))]
PLAN_OUTSIDE = [_plan_window(datetime.datetime(2026, 11, 9, 2, 0), datetime.datetime(2026, 11, 9, 4, 0))]


def _loaded(plan, **overrides):
    """A component with its charger read and car 0's plan published, ready for a fixed-clock tick."""
    component = _make_component(**overrides)
    component.local_tz = CONTROL_TZ
    component.base.local_tz = CONTROL_TZ
    # Read before any plan is published, so the first poll's own control cycle (on the real clock) does nothing
    run_async(component.run(0, True))
    component.base.set_state_wrapper("binary_sensor.predbat_car_charging_slot", "off", {"planned": plan})
    component.transport.writes.clear()
    return component


def test_plan_led_stop_and_release():
    """Outside a window the charger is turned off and held; read only mode turns it back on."""
    component = _loaded(PLAN_OUTSIDE, hanchu_ev_control=True)
    assert component.charger_control_active
    run_async(component.control_tick(CONTROL_NOW))
    assert component.transport.writes == [(SN_A, {"charge_status": 0})]
    assert SN_A in component.stopped_by_predbat and component.charger_control_state == {SN_A: False}

    component.chargers[SN_A].charge_enabled = False
    run_async(component.control_tick(CONTROL_NOW))
    assert component.transport.writes == [(SN_A, {"charge_status": 0})], "nothing more while it stays as set"

    component.base.args["set_read_only"] = True
    run_async(component.control_tick(CONTROL_NOW))
    assert component.transport.writes[-1] == (SN_A, {"charge_status": 1})
    assert component.charger_control_state == {} and not component.stopped_by_predbat
    print("  ✓ Plan-led stop and release")


def test_plan_led_start_and_drift():
    """Inside a window a stopped charger is turned on; a change from the app is put back."""
    chargers = {SN_A: (_entry(status="4"), _detail(status="4", power="0"), _settings(charge="0"))}
    component = _loaded(PLAN_INSIDE, served=chargers, hanchu_ev_control=True)
    run_async(component.control_tick(CONTROL_NOW))
    assert component.transport.writes == [(SN_A, {"charge_status": 1})]
    component.chargers[SN_A].charge_enabled = False
    run_async(component.control_tick(CONTROL_NOW))
    assert component.transport.writes[-1] == (SN_A, {"charge_status": 1}) and _logged(component, "re-applying")
    print("  ✓ Plan-led start and drift correction")


def test_control_leaves_unplugged_stale_and_user_stopped_chargers():
    """No car, a stale record or no plan means no command; a charger the user stopped is not turned on at release."""
    unplugged = {SN_A: (_entry(status="0", gun="2"), _detail(status="0", gun="2", power="0"), _settings())}
    component = _loaded(PLAN_OUTSIDE, served=unplugged, hanchu_ev_control=True)
    run_async(component.control_tick(CONTROL_NOW))
    assert component.transport.writes == []

    component = _loaded(PLAN_OUTSIDE, hanchu_ev_control=True)
    component.stale.add(SN_A)
    run_async(component.control_tick(CONTROL_NOW))
    assert component.transport.writes == []

    nothing_planned = _make_component(hanchu_ev_control=True)
    run_async(nothing_planned.run(0, True))
    assert nothing_planned.transport.writes == [], "before Predbat has planned anything no charger is touched"

    user_off = {SN_A: (_entry(status="4"), _detail(status="4", power="0"), _settings(charge="0"))}
    component = _loaded(PLAN_OUTSIDE, served=user_off, hanchu_ev_control=True)
    component.charger_control_state[SN_A] = False
    run_async(component.charger_control_release())
    assert component.transport.writes == [], "Predbat did not turn it off, so it does not turn it on"
    print("  ✓ Unplugged, stale, unplanned and user-stopped chargers are left alone")


def test_swipe_charge_plugged_in_mid_window():
    """In Swipe Charge mode a plugged-in charger rests off: nothing is sent outside a window, and plugging in mid-window starts it."""
    resting = {SN_A: (_entry(status="1"), _detail(status="1", power="0"), _settings(charge="0", work="0"))}
    component = _loaded(PLAN_OUTSIDE, served=resting, hanchu_ev_control=True)
    run_async(component.control_tick(CONTROL_NOW))
    run_async(component.control_tick(CONTROL_NOW))
    assert component.transport.writes == [], "already off, so no stop is sent"
    assert SN_A not in component.stopped_by_predbat, "Predbat did not stop it, so a release must not start it"

    unplugged = {SN_A: (_entry(status="0", gun="2"), _detail(status="0", gun="2", power="0"), _settings(charge="0", work="0"))}
    component = _loaded(PLAN_INSIDE, served=unplugged, hanchu_ev_control=True)
    run_async(component.control_tick(CONTROL_NOW))
    assert component.transport.writes == [], "no car, nothing to start"
    component.transport.chargers[SN_A] = (_entry(status="1"), _detail(status="1", power="0"), _settings(charge="0", work="0"))
    run_async(component.run(60, False))
    run_async(component.control_tick(CONTROL_NOW))
    assert component.transport.writes == [(SN_A, {"charge_status": 1})], "a car plugged in mid-window is started"
    print("  ✓ Swipe Charge: resting off, started when plugged in mid-window")


def test_control_needs_automatic():
    """Control without automatic configuration is refused with a warning."""
    component = _make_component(hanchu_ev_control=True, automatic=False)
    run_async(component.run(0, True))
    assert not component.charger_control_active and _logged(component, "needs hanchu_ev_automatic")
    print("  ✓ Control needs automatic configuration")


def test_battery_hold_follows_the_plan():
    """With battery_hold on, battery discharge to the charger is disabled inside a window and allowed outside one."""
    component = _loaded(PLAN_INSIDE, battery_hold=True)
    run_async(component.battery_hold_tick(CONTROL_NOW))
    assert component.transport.writes == [(SN_A, {"disable_bat_discharge": 1})]
    run_async(component.battery_hold_tick(CONTROL_NOW))
    assert len(component.transport.writes) == 1, "written once, not every cycle"

    component.base.set_state_wrapper("binary_sensor.predbat_car_charging_slot", "off", {"planned": PLAN_OUTSIDE})
    run_async(component.battery_hold_tick(CONTROL_NOW))
    assert component.transport.writes[-1] == (SN_A, {"disable_bat_discharge": 0})

    read_only = _loaded(PLAN_INSIDE, battery_hold=True)
    read_only.base.args["set_read_only"] = True
    run_async(read_only.battery_hold_tick(CONTROL_NOW))
    assert read_only.transport.writes == []

    off = _loaded(PLAN_INSIDE)
    run_async(off.battery_hold_tick(CONTROL_NOW))
    assert off.transport.writes == []

    failing = _loaded(PLAN_INSIDE, battery_hold=True)
    failing.transport.errors[("write_settings", SN_A)] = HanchuEVApiError("busy")
    run_async(failing.battery_hold_tick(CONTROL_NOW))
    assert _logged(failing, "could not set battery discharge") and failing.chargers[SN_A].battery_discharge_disabled is False
    print("  ✓ Battery hold follows the plan")


def test_battery_hold_follows_octopus_dispatches():
    """An Octopus Intelligent dispatch running now also disables battery discharge to the charger."""
    component = _loaded([], battery_hold=True)
    dispatch = {"start": "2026-11-08T23:00:00+0000", "end": "2026-11-09T00:30:00+0000"}
    component.base.args["octopus_intelligent_slot"] = ["binary_sensor.octopus_dispatching"]
    component.base.set_state_wrapper("binary_sensor.octopus_dispatching", "on", {"planned_dispatches": [dispatch]})
    run_async(component.battery_hold_tick(CONTROL_NOW))
    assert component.transport.writes == [(SN_A, {"disable_bat_discharge": 1})]
    print("  ✓ Battery hold follows Octopus dispatches")


def test_hanchu_ev(my_predbat=None):
    """Run every Hanchu EV charger test."""
    print("=" * 70)
    print("Hanchu EV charger tests")
    print("=" * 70)
    test_aes_fips197_vector()
    test_encrypt_body_matches_reference()
    test_normalise_charging()
    test_normalise_handles_missing_and_junk()
    test_plugged_state()
    test_transport_signs_in_then_calls_encrypted()
    test_transport_signs_in_again_once_on_401()
    test_transport_bad_credentials()
    test_transport_failures()
    test_transport_finds_stations_and_chargers()
    test_component_registration()
    test_component_settings()
    test_component_publishes_one_charger()
    test_component_automatic_config_and_filter()
    test_controls_are_queued_then_written()
    test_failed_reads_mark_stale_and_auth_failure()
    test_plan_led_stop_and_release()
    test_plan_led_start_and_drift()
    test_control_leaves_unplugged_stale_and_user_stopped_chargers()
    test_swipe_charge_plugged_in_mid_window()
    test_control_needs_automatic()
    test_battery_hold_follows_the_plan()
    test_battery_hold_follows_octopus_dispatches()
    print("=" * 70)
    return False
