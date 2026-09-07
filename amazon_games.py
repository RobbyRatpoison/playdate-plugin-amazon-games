"""
Amazon Games plugin for PlayDate.

Sync sources (tried in order):
  1. Nile JSON files -- written by Heroic Games Launcher / Nile client; zero auth needed.
  2. Amazon's own device-registration OAuth2 flow + GetEntitlements RPC.

Auth (source 2) follows Nile's real protocol (github.com/NearlyTRex/Nile), not a
cookie scrape: a PKCE authorization-code flow against amazon.com/ap/signin,
registering a virtual "AGSLauncher for Windows" device at api.amazon.com/auth/register
to get a real bearer token + refresh token. The previous version of this plugin
scraped an `at-main` session cookie out of the popup instead -- fragile (an
at-main cookie's own login-session lifetime, not a proper OAuth grant) and never
actually confirmed working end to end.

Library sync (source 2) calls the same GetEntitlements RPC the real Amazon Games
launcher itself uses (an SDS-style RPC via the "AnimusDistributionService", not the
gaming.amazon.com GraphQL API the old version called -- that API mixes in Prime
benefits and non-launcher entries; GetEntitlements only ever returns games launchable
through Amazon Games itself, no productLine filtering needed).

Install/launch/uninstall are a from-scratch reimplementation of Amazon's real
download protocol, not a wrapper around the Nile CLI (that would depend on a
third-party tool being installed, and be inconsistent with how auth/sync are
built here): GetGameDownload -> a signed, LZMA-compressed SDS manifest (see
sds_manifest.py) -> content-hash-addressed file downloads -> the installed
game's own fuel.json launch descriptor, run through Proton/Wine (runners.proton
/ runners.wine) with the Fuel SDK env vars real Amazon games read at startup
(see _ensure_sdk()). Nile's local library.json/installed.json files are still
read as an optional zero-auth sync source (_sync_from_nile) -- that's reading
a config file, not shelling out to Nile's binary, so it's a different thing.
"""

import base64
import hashlib
import json
import logging
import os
import re
import secrets
import threading
import time
import uuid
from urllib.parse import urlencode, urlparse, urlunparse, parse_qs

import requests

from config import load_config, _save_config_data, BASE_DIR
from database import get_db, next_negative_appid, update_game_data

from . import sds_manifest

log = logging.getLogger(__name__)

AMAZON_API                             = 'https://api.amazon.com'
AMAZON_GAMING_DISTRIBUTION_ENTITLEMENTS = 'https://gaming.amazon.com/api/distribution/entitlements'
AMAZON_GAMING_DISTRIBUTION              = 'https://gaming.amazon.com/api/distribution/v2/public'
# Amazon's own SDK self-update channel -- a fixed, unauthenticated distribution
# channel (not tied to any game entitlement) that carries the Fuel SDK DLLs
# every native Amazon game reads at startup. Same GUID Nile itself uses.
AMAZON_SDK_CHANNEL_URL = f'{AMAZON_GAMING_DISTRIBUTION}/download/channel/87d38116-4cbf-4af0-a371-a5b498975346'
MARKETPLACE_ID                          = 'ATVPDKIKX0DER'
APP_NAME                                = 'AGSLauncher for Windows'
APP_VERSION                             = '1.0.0'
CLIENT_UA                               = 'com.amazon.agslauncher.win/3.0.9202.1'

# Where PlayDate installs Amazon games / caches the Fuel SDK. games_dir is
# user-configurable via runners.installdir (Set Folder / Open Folder), same
# pattern as GOG/Humble/itch.io/IndieGala.
AMAZON_INSTALL_BASE = os.path.expanduser('~/Games/AmazonGames')
AMAZON_SDK_DIR       = os.path.join(BASE_DIR, 'amazon_games_sdk')

# Nile (Heroic backend) library file locations
NILE_PATHS = [
    os.path.expanduser('~/.config/nile/library.json'),
    os.path.expanduser('~/.config/heroic/nile_config/nile/library.json'),
    os.path.expanduser('~/.var/app/com.heroicgameslauncher.hgl/config/heroic/nile_config/nile/library.json'),
]
NILE_INSTALLED_PATHS = [
    os.path.expanduser('~/.config/nile/installed.json'),
    os.path.expanduser('~/.config/heroic/nile_config/nile/installed.json'),
    os.path.expanduser('~/.var/app/com.heroicgameslauncher.hgl/config/heroic/nile_config/nile/installed.json'),
]

_sync_state = {'running': False, 'status': '', 'added': 0, 'updated': 0, 'error': None, 'source': None}
_sync_lock  = threading.Lock()

# One in-flight OAuth attempt's PKCE state. A single-user desktop popup flow
# only ever has one attempt open at a time, so a module-level dict (not
# per-session storage) is enough -- same pattern as every other plugin's
# single-shot auth popup here.
_pending_auth = {}


# ── Config ──────────────────────────────────────────────────────────────────────

def _cfg():
    return (load_config() or {}).get('amazon_games', {})

def _save_cfg(data):
    cfg = load_config() or {}
    cfg['amazon_games'] = data
    _save_config_data(cfg)

def is_connected():
    return bool(_cfg().get('access_token')) or bool(find_nile_library())

def get_username():
    return _cfg().get('username', 'Connected')

def find_nile_library():
    for p in NILE_PATHS:
        if os.path.isfile(p):
            return p
    return None

def find_nile_installed():
    for p in NILE_INSTALLED_PATHS:
        if os.path.isfile(p):
            return p
    return None

def nile_detected():
    return find_nile_library() is not None


# ── Auth (device-registration OAuth2, matching Nile's real protocol) ────────────

def _generate_pkce():
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b'=')
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier).digest()).rstrip(b'=')
    return verifier, challenge


def get_auth_url():
    """Starts a new device-registration attempt and returns the amazon.com/ap/signin
    URL to sign in at. The PKCE verifier/client_id/serial generated here are held
    in _pending_auth until exchange_code() consumes them."""
    verifier, challenge = _generate_pkce()
    serial = uuid.uuid1().hex.upper()
    client_id = f'{serial}#A2UMVHOX7UP4V7'.encode('ascii').hex()

    _pending_auth.clear()
    _pending_auth.update({'verifier': verifier.decode('ascii'), 'serial': serial, 'client_id': client_id})

    params = {
        'openid.ns':                  'http://specs.openid.net/auth/2.0',
        'openid.claimed_id':          'http://specs.openid.net/auth/2.0/identifier_select',
        'openid.identity':            'http://specs.openid.net/auth/2.0/identifier_select',
        'openid.mode':                'checkid_setup',
        'openid.oa2.scope':           'device_auth_access',
        'openid.ns.oa2':              'http://www.amazon.com/ap/ext/oauth/2',
        'openid.oa2.response_type':   'code',
        'openid.oa2.code_challenge_method': 'S256',
        'openid.oa2.client_id':       f'device:{client_id}',
        'language':                   'en_US',
        'marketPlaceId':              MARKETPLACE_ID,
        'openid.return_to':           'https://www.amazon.com',
        'openid.pape.max_auth_age':   0,
        'openid.assoc_handle':        'amzn_sonic_games_launcher',
        'pageId':                     'amzn_sonic_games_launcher',
        'openid.oa2.code_challenge':  challenge.decode('ascii'),
    }
    return 'https://amazon.com/ap/signin?' + urlencode(params)


def exchange_code(redirect_url_or_code):
    """redirect_url_or_code is whatever the popup's code_js captured -- the full
    landing URL (containing openid.oa2.authorization_code=...) or, if something
    upstream already extracted it, a bare code. Returns (True, username) or
    (False, message)."""
    raw = (redirect_url_or_code or '').strip()
    if not _pending_auth:
        return False, 'Login session expired -- try connecting again.'

    code = raw
    if 'openid.oa2.authorization_code' in raw:
        qs = parse_qs(urlparse(raw).query)
        code = (qs.get('openid.oa2.authorization_code') or [''])[0]
    if not code:
        return False, 'Could not find an authorization code in the login result -- try again.'

    verifier   = _pending_auth.get('verifier', '')
    serial     = _pending_auth.get('serial', '')
    client_id  = _pending_auth.get('client_id', '')
    _pending_auth.clear()

    data = {
        'auth_data': {
            'authorization_code':        code,
            'client_domain':             'DeviceLegacy',
            'client_id':                 client_id,
            'code_algorithm':            'SHA-256',
            'code_verifier':             verifier,
            'use_global_authentication': False,
        },
        'registration_data': {
            'app_name':      APP_NAME,
            'app_version':   APP_VERSION,
            'device_model':  'Windows',
            'device_name':   None,
            'device_serial': serial,
            'device_type':   'A2UMVHOX7UP4V7',
            'domain':        'Device',
            'os_version':    '10.0.19044.0',
        },
        'requested_extensions': ['customer_info', 'device_info'],
        'requested_token_type': ['bearer', 'mac_dms'],
        'user_context_map': {},
    }
    try:
        resp = requests.post(f'{AMAZON_API}/auth/register', json=data, timeout=20)
    except requests.RequestException as e:
        return False, f'Could not reach Amazon: {e}'
    if not resp.ok:
        log.warning('Amazon device registration failed: HTTP %d: %s', resp.status_code, resp.text[:300])
        return False, f'Amazon rejected the login (HTTP {resp.status_code}) -- try again.'

    try:
        success = resp.json()['response']['success']
        access_token  = success['tokens']['bearer']['access_token']
        refresh_token = success['tokens']['bearer']['refresh_token']
        expires_in    = int(success['tokens']['bearer'].get('expires_in', 3600))
        device_serial = success['extensions']['device_info']['device_serial_number']
        username      = success['extensions']['customer_info'].get('given_name') or 'Connected'
    except (KeyError, ValueError) as e:
        log.warning('Amazon device registration: unexpected response shape: %s', e)
        return False, 'Amazon returned an unexpected response -- see playdate.log.'

    _save_cfg({
        'access_token':  access_token,
        'refresh_token': refresh_token,
        'expires_at':    int(time.time()) + expires_in,
        'device_serial': device_serial,
        'username':      username,
    })
    log.info('Amazon Games: connected as %r', username)
    return True, username


def _refresh_access_token():
    cfg = _cfg()
    refresh_token = cfg.get('refresh_token', '')
    if not refresh_token:
        return None
    try:
        resp = requests.post(f'{AMAZON_API}/auth/token', json={
            'source_token':        refresh_token,
            'source_token_type':   'refresh_token',
            'requested_token_type': 'access_token',
            'app_name':            APP_NAME,
            'app_version':         APP_VERSION,
        }, timeout=20)
    except requests.RequestException as e:
        log.warning('Amazon: token refresh failed: %s', e)
        return None
    if not resp.ok:
        log.warning('Amazon: token refresh HTTP %d', resp.status_code)
        return None
    data = resp.json()
    cfg['access_token'] = data['access_token']
    cfg['expires_at']   = int(time.time()) + int(data.get('expires_in', 3600))
    _save_cfg(cfg)
    return cfg['access_token']


def _get_valid_access_token():
    cfg = _cfg()
    if not cfg.get('access_token'):
        return None
    if time.time() > cfg.get('expires_at', 0) - 60:
        return _refresh_access_token()
    return cfg['access_token']


def disconnect():
    cfg = load_config() or {}
    cfg.pop('amazon_games', None)
    _save_config_data(cfg)


# ── Library sync via GetEntitlements ────────────────────────────────────────────

def _entitlements_request(token, device_serial, next_token=None, sync_point=None):
    headers = {
        'X-Amz-Target':     'com.amazon.animusdistributionservice.entitlement.AnimusEntitlementsService.GetEntitlements',
        'x-amzn-token':     token,
        'UserAgent':        CLIENT_UA,
        'Content-Type':     'application/json',
        'Content-Encoding': 'amz-1.0',
    }
    body = {
        'Operation':       'GetEntitlements',
        'clientId':        'Sonic',
        'syncPoint':       sync_point,
        'nextToken':       next_token,
        'maxResults':      50,
        'productIdFilter': None,
        'keyId':           'd5dc8b8b-86c8-4fc4-ae93-18c0def5314d',
        'hardwareHash':    hashlib.sha256(device_serial.encode()).hexdigest().upper(),
    }
    return requests.post(AMAZON_GAMING_DISTRIBUTION_ENTITLEMENTS, headers=headers, json=body, timeout=20)


def _distribution_request(target, token, body):
    """Generic AnimusDistributionService RPC dispatch -- every distribution
    call (GetGameDownload, GetLiveVersionIds, ...) POSTs to the same base
    URL, differentiated only by the X-Amz-Target header. GetEntitlements is
    the one exception, served from its own endpoint (see _entitlements_request)."""
    headers = {
        'X-Amz-Target':     target,
        'x-amzn-token':     token,
        'UserAgent':        CLIENT_UA,
        'Content-Type':     'application/json',
        'Content-Encoding': 'amz-1.0',
    }
    return requests.post(AMAZON_GAMING_DISTRIBUTION, headers=headers, json=body, timeout=30)


def _get_game_download(game_id, token):
    """GetGameDownload -- returns {'downloadUrl': ..., 'versionId': ...} for
    an owned entitlement id, the same call the real Amazon Games launcher
    (and Nile) makes right before downloading a game."""
    resp = _distribution_request(
        'com.amazon.animusdistributionservice.external.AnimusDistributionService.GetGameDownload',
        token, {'entitlementId': game_id, 'Operation': 'GetGameDownload'},
    )
    if not resp.ok:
        raise RuntimeError(f'GetGameDownload failed (HTTP {resp.status_code})')
    data = resp.json()
    if not data.get('downloadUrl'):
        raise RuntimeError('Amazon did not return a download URL for this game')
    return data


def _manifest_url(download_url):
    parts = urlparse(download_url)
    return urlunparse(parts._replace(path=parts.path + '/manifest.proto'))


def _file_url(download_url, file_hash_hex):
    parts = urlparse(download_url)
    return urlunparse(parts._replace(path=parts.path + '/files/' + file_hash_hex))


def _fetch_manifest(download_url, verify=True):
    resp = requests.get(_manifest_url(download_url), timeout=30)
    resp.raise_for_status()
    return sds_manifest.parse_manifest(resp.content, verify=verify)


def _ensure_sdk():
    """One-time fetch of Amazon's Fuel SDK (FuelSDK_x64.dll / AmazonGamesSDK_*.dll)
    -- every native Amazon game reads these via the env vars launch_game() sets,
    matching Nile's SelfUpdateHandler.get_sdk(). Best-effort: a game may still
    run without it, so failures here are logged, not raised."""
    marker = os.path.join(AMAZON_SDK_DIR, '.done')
    if os.path.isfile(marker):
        return AMAZON_SDK_DIR
    try:
        resp = requests.get(AMAZON_SDK_CHANNEL_URL, timeout=20)
        resp.raise_for_status()
        channel = resp.json()
        manifest = _fetch_manifest(channel['downloadUrl'], verify=True)
        wrote = 0
        for pkg in manifest.packages:
            for f in pkg.files:
                if 'FuelSDK_x64.dll' not in f.path and 'AmazonGamesSDK_' not in f.path:
                    continue
                dest = os.path.join(AMAZON_SDK_DIR, f.path.replace('\\', os.sep).replace('/', os.sep))
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                fresp = requests.get(_file_url(channel['downloadUrl'], f.hash.value), timeout=60, stream=True)
                fresp.raise_for_status()
                with open(dest, 'wb') as fh:
                    for chunk in fresp.iter_content(1024 * 1024):
                        fh.write(chunk)
                wrote += 1
        os.makedirs(AMAZON_SDK_DIR, exist_ok=True)
        with open(marker, 'w') as fh:
            fh.write('1')
        log.info('Amazon: Fuel SDK downloaded (%d files) to %s', wrote, AMAZON_SDK_DIR)
    except Exception as e:
        log.warning('Amazon: Fuel SDK download failed (some games may fail to start): %s', e)
    return AMAZON_SDK_DIR


def _read_fuel_json(install_path):
    """Every native Amazon game ships a fuel.json launch descriptor at the
    root of its install -- the authoritative source for which exe to run,
    what args to pass, and any working-directory override. Read fresh at
    launch time rather than cached, so it's always in sync with the files
    on disk."""
    fuel_path = os.path.join(install_path, 'fuel.json')
    if not os.path.isfile(fuel_path):
        return None
    try:
        with open(fuel_path, 'r', encoding='utf-8') as fh:
            data = json.load(fh)
    except Exception as e:
        log.warning('Amazon: failed to parse fuel.json: %s', e)
        return None
    main = data.get('Main') or {}
    command = (main.get('Command') or '').replace('\\', os.sep)
    if not command:
        return None
    cwd_override = (main.get('WorkingSubdirOverride') or '').replace('\\', os.sep) or None
    return {'command': command, 'args': main.get('Args') or [], 'cwd_override': cwd_override}


def _file_matches_hash(path, file_obj):
    if file_obj.hash.algorithm != 'sha256' or not os.path.isfile(path):
        return False
    h = hashlib.sha256()
    with open(path, 'rb') as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest() == file_obj.hash.value


def get_sync_state():
    return dict(_sync_state)


def start_library_sync(source='auto'):
    with _sync_lock:
        if _sync_state['running']:
            return {'status': 'already_running'}
        _sync_state.update({
            'running': True, 'status': 'Starting…',
            'added': 0, 'updated': 0, 'error': None, 'source': source,
        })
    threading.Thread(target=_run_sync, args=(source,), daemon=True).start()
    return {'status': 'started'}


def _run_sync(source):
    try:
        nile_path = find_nile_library()
        if source == 'auto':
            source = 'nile' if nile_path else 'api'

        if source == 'nile' and nile_path:
            _sync_from_nile(nile_path)
        else:
            _sync_from_api()
    except Exception as e:
        log.error('Amazon sync error: %s', e, exc_info=True)
        _sync_state.update({'running': False, 'status': '', 'error': str(e)})


def _sync_from_nile(library_path):
    _sync_state['status'] = 'Reading Nile library…'
    log.info('Amazon: syncing from Nile at %s', library_path)

    try:
        with open(library_path, 'r', encoding='utf-8') as f:
            raw = json.load(f)
    except Exception as e:
        raise RuntimeError(f'Could not read Nile library file: {e}')

    games = raw.get('library', raw.get('games', [])) if isinstance(raw, dict) else raw

    installed_ids = set()
    nile_inst = find_nile_installed()
    if nile_inst:
        try:
            with open(nile_inst, 'r', encoding='utf-8') as f:
                inst_raw = json.load(f)
            if isinstance(inst_raw, list):
                installed_ids = {g.get('id', '') for g in inst_raw}
            elif isinstance(inst_raw, dict):
                installed_ids = set(inst_raw.keys())
        except Exception as e:
            log.warning('Amazon: could not read Nile installed.json: %s', e)

    db = get_db()
    existing = {
        row['platform_id']: row['appid']
        for row in db.execute("SELECT appid, platform_id FROM games WHERE platform='amazon_games'").fetchall()
    }
    blacklisted = {
        row[0] for row in db.execute(
            "SELECT platform_id FROM blacklist WHERE platform_id IS NOT NULL"
        ).fetchall()
    }

    added = updated = 0
    for game in games:
        # Nile's own JSON shape: {"id": <entitlement id>, "product": {"id", "title", ...}}
        product  = game.get('product') or game
        game_id  = str(product.get('id') or game.get('id') or '').strip()
        if not game_id or game_id in blacklisted:
            continue
        name = (product.get('title') or game_id).strip()
        installed = 1 if game_id in installed_ids else 0
        # platform_appname reused to hold Amazon's product SKU (not the entitlement
        # id) -- launch_game() needs it for the AMAZON_GAMES_FUEL_PRODUCT_SKU env
        # var, same repurposing precedent as Epic's own use of this column.
        sku = (product.get('sku') or '').strip() or None

        if game_id in existing:
            update_game_data(existing[game_id], installed=installed, **({'platform_appname': sku} if sku else {}))
            updated += 1
        else:
            appid = next_negative_appid(db)
            db.execute(
                """INSERT OR IGNORE INTO games
                   (appid, name, platform, platform_id, platform_appname,
                    date_added, completion_status, installed,
                    art_fetched, meta_fetched, cheevos_fetched,
                    protondb_fetched, hltb_fetched)
                   VALUES (?, ?, 'amazon_games', ?, ?,
                           ?, 'Never Played', ?,
                           '0', '0', '0', '0', '0')""",
                (appid, name, game_id, sku, int(time.time()), installed),
            )
            db.commit()
            existing[game_id] = appid
            added += 1
            log.info('Amazon (Nile): added %r', name)
            _fetch_art(appid, name)

    db.close()
    _sync_state.update({
        'running': False,
        'status': f'Done (via Nile) — {added} added, {updated} updated.',
        'added': added, 'updated': updated,
    })
    log.info('Amazon Nile sync complete: %d added, %d updated', added, updated)


def _sync_from_api():
    token = _get_valid_access_token()
    if not token:
        raise RuntimeError('Not connected — please connect your Amazon account first.')
    device_serial = _cfg().get('device_serial', '')

    db = get_db()
    existing = {
        row['platform_id']: row['appid']
        for row in db.execute("SELECT appid, platform_id FROM games WHERE platform='amazon_games'").fetchall()
    }
    blacklisted = {
        row[0] for row in db.execute(
            "SELECT platform_id FROM blacklist WHERE platform_id IS NOT NULL"
        ).fetchall()
    }

    added = updated = 0
    next_token = None
    page = 1

    while True:
        _sync_state['status'] = f'Fetching library page {page}…'
        try:
            resp = _entitlements_request(token, device_serial, next_token=next_token)
        except requests.RequestException as e:
            raise RuntimeError(f'Network error contacting Amazon: {e}')
        if not resp.ok:
            raise RuntimeError(f'GetEntitlements failed (HTTP {resp.status_code}) — try reconnecting.')
        data = resp.json()

        entries = data.get('entitlements') or []
        log.info('Amazon GetEntitlements page %d: %d items', page, len(entries))

        for entry in entries:
            product = entry.get('product') or {}
            game_id = str(product.get('id') or '').strip()
            if not game_id or game_id in blacklisted:
                continue
            name = (product.get('title') or game_id).strip()
            # platform_appname reused to hold Amazon's product SKU (see _sync_from_nile).
            sku  = (product.get('sku') or '').strip() or None
            genres = ''
            try:
                genres = ','.join(product['productDetail']['details']['genres'])
            except (KeyError, TypeError):
                pass

            if game_id in existing:
                if sku:
                    try:
                        update_game_data(existing[game_id], platform_appname=sku)
                    except Exception as e:
                        log.warning('Amazon: SKU backfill failed for %r: %s', name, e)
                updated += 1
            else:
                appid = next_negative_appid(db)
                db.execute(
                    """INSERT OR IGNORE INTO games
                       (appid, name, platform, platform_id, platform_appname,
                        date_added, completion_status, installed,
                        art_fetched, meta_fetched, cheevos_fetched,
                        protondb_fetched, hltb_fetched)
                       VALUES (?, ?, 'amazon_games', ?, ?,
                               ?, 'Never Played', 0,
                               '0', '0', '0', '0', '0')""",
                    (appid, name, game_id, sku, int(time.time())),
                )
                db.commit()
                if genres:
                    try:
                        update_game_data(appid, genres=genres)
                    except Exception as e:
                        log.warning('Amazon: genres update failed for %r: %s', name, e)
                existing[game_id] = appid
                added += 1
                log.info('Amazon API: added %r', name)
                _fetch_art(appid, name)

        next_token = data.get('nextToken')
        if not next_token or not entries:
            break
        page += 1
        time.sleep(0.5)

    db.close()
    _sync_state.update({
        'running': False,
        'status': f'Done (via API) — {added} added, {updated} already in library.',
        'added': added, 'updated': updated,
    })
    log.info('Amazon API sync complete: %d added, %d existing', added, updated)


# ── Art ─────────────────────────────────────────────────────────────────────────

def _fetch_art(appid, name):
    try:
        from images import _sgdb_search_game_id, download_vertical, download_horizontal
        from datetime import date
        sgdb_id = _sgdb_search_game_id(name)
        vert  = download_vertical(appid, sgdb_id=sgdb_id, game_name=name)
        horiz = download_horizontal(appid, sgdb_id=sgdb_id, game_name=name)
        if vert != 'missing' or horiz != 'missing':
            update_game_data(appid, art_fetched=date.today().isoformat())
            log.info('Amazon: art fetched for %r', name)
    except Exception as e:
        log.warning('Amazon: art fetch failed for %r: %s', name, e)


# ── Install ──────────────────────────────────────────────────────────────────
#
# Native implementation of Amazon's real download protocol (GetGameDownload ->
# signed/LZMA-compressed SDS manifest -> content-hash-addressed file downloads),
# reimplemented from Nile's actual source rather than shelling out to its CLI --
# consistent with how auth/library sync were built, and with this project's
# standing precedent against depending on a third-party launcher tool being
# installed (see PLUGINS.md / CLAUDE.md). Nile's own local library.json/
# installed.json files are still read as an optional zero-auth sync source
# (_sync_from_nile above) -- that's just reading a config file, not shelling
# out to Nile's binary, so it stays.

_install_states  = {}   # appid (int) -> dict
_install_lock    = threading.Lock()
_install_cancels = {}   # appid (int) -> threading.Event


def install_game(appid, progress_cb=None, cancel_ev=None):
    """
    Download and install an owned Amazon game.

    Returns {'status': 'success'|'error'|'cancelled', 'install_path': str,
             'name': str, 'message': str}
    """
    db  = get_db()
    row = db.execute("SELECT name, platform_id FROM games WHERE appid = ?", (appid,)).fetchone()
    db.close()
    if not row:
        return {'status': 'error', 'message': f'Game not found (appid {appid})'}
    name, game_id = row['name'], row['platform_id']

    token = _get_valid_access_token()
    if not token:
        return {'status': 'error', 'message': 'Not connected — please connect your Amazon account first.'}

    try:
        download_info = _get_game_download(game_id, token)
    except Exception as e:
        return {'status': 'error', 'message': f'Could not get download info: {e}'}
    download_url = download_info['downloadUrl']

    try:
        manifest = _fetch_manifest(download_url, verify=True)
    except sds_manifest.ManifestVerificationError as e:
        return {'status': 'error', 'message': f'Manifest signature check failed: {e}'}
    except Exception as e:
        return {'status': 'error', 'message': f'Could not fetch manifest: {e}'}

    if not manifest.packages or not manifest.packages[0].files:
        return {'status': 'error', 'message': f'{name!r} has no downloadable files.'}
    files      = manifest.packages[0].files
    total_size = sum(f.size for f in files)

    from runners.installdir import get_install_dir, check_writable
    safe_name    = re.sub(r'[^\w\s.-]', '', name).strip() or game_id
    install_path = os.path.join(get_install_dir('amazon_games', AMAZON_INSTALL_BASE), safe_name)
    os.makedirs(install_path, exist_ok=True)

    try:
        check_writable(install_path)
        from runners.diskspace import check_disk_space
        check_disk_space(install_path, total_size)
    except RuntimeError as e:
        return {'status': 'error', 'message': str(e), 'install_path': install_path}

    _ensure_sdk()

    done_bytes = 0
    for f in files:
        if cancel_ev and cancel_ev.is_set():
            return {'status': 'cancelled', 'message': 'Install cancelled', 'name': name}

        rel_path  = f.path.replace('\\', os.sep).replace('/', os.sep)
        dest_path = os.path.join(install_path, rel_path)
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)

        if _file_matches_hash(dest_path, f):
            done_bytes += f.size
            if progress_cb:
                progress_cb(done_bytes, total_size)
            continue

        try:
            resp = requests.get(_file_url(download_url, f.hash.value), timeout=60, stream=True)
            resp.raise_for_status()
            with open(dest_path, 'wb') as fh:
                for chunk in resp.iter_content(1024 * 1024):
                    if cancel_ev and cancel_ev.is_set():
                        raise InterruptedError('cancelled')
                    fh.write(chunk)
                    done_bytes += len(chunk)
                    if progress_cb:
                        progress_cb(done_bytes, total_size)
        except InterruptedError:
            return {'status': 'cancelled', 'message': 'Install cancelled', 'name': name}
        except Exception as e:
            log.error('Amazon install: download failed for %s: %s', f.path, e)
            return {'status': 'error', 'message': f'Download failed for {f.path}: {e}',
                    'install_path': install_path}

        if not _file_matches_hash(dest_path, f):
            return {'status': 'error', 'message': f'Checksum mismatch for {f.path}',
                    'install_path': install_path}

    fuel = _read_fuel_json(install_path)
    if not fuel:
        return {'status': 'error',
                'message': f'Downloaded {name!r} but could not find its fuel.json launch descriptor.',
                'install_path': install_path}

    wine_prefix = os.path.join(install_path, 'prefix')
    os.makedirs(wine_prefix, exist_ok=True)

    update_game_data(appid, install_path=install_path, installed=1,
                      platform_executable=fuel['command'], wine_prefix=wine_prefix)
    log.info('Amazon: installed %r -> %s', name, install_path)
    return {'status': 'success', 'install_path': install_path, 'name': name}


def start_install(appid):
    """Start an install in a background thread. Returns immediately;
    poll get_install_state(appid) for progress."""
    db  = get_db()
    row = db.execute("SELECT name FROM games WHERE appid = ?", (appid,)).fetchone()
    db.close()
    name = row['name'] if row else 'Amazon Game'

    with _install_lock:
        if _install_states.get(appid, {}).get('status') == 'running':
            return {'status': 'already_running'}
        cancel_ev = threading.Event()
        _install_cancels[appid] = cancel_ev
        _install_states[appid]  = {'status': 'running', 'done': 0, 'total': 0,
                                    'name': name, 'message': 'Starting download…'}

    def _progress(done, total):
        with _install_lock:
            _install_states[appid].update({'done': done, 'total': total})

    def _run():
        try:
            result = install_game(appid, progress_cb=_progress, cancel_ev=cancel_ev)
            with _install_lock:
                _install_states[appid] = {**result, 'name': result.get('name', name)}
        except Exception as e:
            log.error('Amazon start_install thread: %s', e, exc_info=True)
            with _install_lock:
                _install_states[appid] = {'status': 'error', 'message': str(e), 'name': name}
        finally:
            _install_cancels.pop(appid, None)

    threading.Thread(target=_run, daemon=True).start()
    return {'status': 'started'}


def cancel_install(appid):
    ev = _install_cancels.get(appid)
    if ev:
        ev.set()


def get_install_state(appid):
    with _install_lock:
        return dict(_install_states.get(appid, {'status': 'not_started'}))


def get_active_install():
    with _install_lock:
        for appid, state in _install_states.items():
            if state.get('status') == 'running':
                return {'appid': appid, **state}
    return {'appid': None}


# ── Launch ───────────────────────────────────────────────────────────────────

def launch_game(appid):
    db  = get_db()
    row = db.execute(
        "SELECT name, install_path, installed, wine_prefix, runner_path, platform_id, platform_appname "
        "FROM games WHERE appid = ?", (appid,)
    ).fetchone()
    db.close()
    if not row:
        return {'status': 'error', 'message': 'Game not found'}

    if not row['installed'] or not row['install_path']:
        result = start_install(appid)
        if result.get('status') == 'already_running':
            return {'status': 'installing', 'install_poller': 'amazonInstallPoll'}
        return {'status': 'installing', 'install_poller': 'amazonInstallPoll',
                'message': f'Installing {row["name"]}…'}

    install_path = row['install_path']
    fuel = _read_fuel_json(install_path)
    if not fuel:
        return {'status': 'error',
                'message': f'Could not find {row["name"]}\'s launch descriptor (fuel.json).'}

    exe_abs = os.path.join(install_path, fuel['command'])
    if not os.path.isfile(exe_abs):
        return {'status': 'error', 'message': f'Executable not found: {exe_abs}'}
    cwd = os.path.join(install_path, fuel['cwd_override']) if fuel['cwd_override'] else os.path.dirname(exe_abs)

    wine_prefix = row['wine_prefix'] or os.path.join(install_path, 'prefix')
    os.makedirs(wine_prefix, exist_ok=True)

    sdk_dir = _ensure_sdk()
    env_extra = {
        'FUEL_DIR':                         os.path.join(sdk_dir, 'Legacy'),
        'AMAZON_GAMES_SDK_PATH':            os.path.join(sdk_dir, 'AmazonGamesSDK'),
        'AMAZON_GAMES_FUEL_ENTITLEMENT_ID': row['platform_id'] or '',
        'AMAZON_GAMES_FUEL_DISPLAY_NAME':   get_username() or '',
    }
    if row['platform_appname']:
        env_extra['AMAZON_GAMES_FUEL_PRODUCT_SKU'] = row['platform_appname']

    try:
        from runners.launch import check_launch
        from runners.proton import get_default_proton, launch_game as _proton_launch
        proton = get_default_proton()
        if proton:
            proc = _proton_launch(install_path, fuel['command'], wine_prefix,
                                  proton_path=row['runner_path'] or proton['path'],
                                  env_extra=env_extra, args=fuel['args'], cwd=cwd)
        else:
            log.info('Amazon: no Proton found, falling back to Wine for %r', row['name'])
            from runners.wine import run_in_prefix
            proc = run_in_prefix(prefix_path=wine_prefix, exe=exe_abs, args=fuel['args'],
                                 env_extra=env_extra, cwd=cwd)
        err = check_launch(proc)
        if err:
            log.error('Amazon: %s', err['message'])
            return err
    except Exception as e:
        return {'status': 'error', 'message': f'Launch failed: {e}'}

    return {'status': 'success'}


# ── Uninstall ────────────────────────────────────────────────────────────────

def uninstall_game(appid):
    import shutil
    db  = get_db()
    row = db.execute("SELECT name, install_path FROM games WHERE appid = ?", (appid,)).fetchone()
    db.close()
    if not row:
        return {'status': 'error', 'message': 'Amazon game not found'}

    install_path = os.path.realpath(row['install_path']) if row['install_path'] else None
    if install_path and os.path.isdir(install_path):
        try:
            shutil.rmtree(install_path)
            log.info('Amazon uninstall: deleted %s', install_path)
        except Exception as e:
            log.error('Amazon uninstall: delete failed for %s — %s', install_path, e)
            return {'status': 'error', 'message': f'Failed to delete game files: {e}'}

    update_game_data(appid, installed=0, install_path=None,
                      platform_executable=None, runner_path=None, wine_prefix=None)
    log.info('Amazon: uninstalled %r', row['name'])
    return {'status': 'success'}
