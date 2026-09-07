from flask import Blueprint, jsonify, request

bp = Blueprint('amazon_games', __name__, url_prefix='/api/amazon_games',
               template_folder='templates')


@bp.route('/auth-url')
def auth_url():
    from .amazon_games import get_auth_url
    return jsonify({'url': get_auth_url()})


@bp.route('/connect', methods=['POST'])
def connect():
    from .amazon_games import exchange_code
    data  = request.get_json(silent=True) or {}
    code  = (data.get('code') or data.get('token') or '').strip()
    if not code:
        return jsonify({'error': 'No login result provided'}), 400
    ok, msg = exchange_code(code)
    if not ok:
        return jsonify({'error': msg}), 401
    return jsonify({'status': 'connected', 'username': msg})


@bp.route('/disconnect', methods=['POST'])
def disconnect():
    from .amazon_games import disconnect as _disconnect
    _disconnect()
    return jsonify({'status': 'disconnected'})


@bp.route('/status')
def status():
    from .amazon_games import is_connected, get_username, nile_detected
    connected = is_connected()
    return jsonify({
        'connected': connected,
        'username':  get_username() if connected else None,
        'nile':      nile_detected(),
    })


@bp.route('/sync', methods=['POST'])
def sync():
    from .amazon_games import start_library_sync, is_connected
    if not is_connected():
        return jsonify({'error': 'Not connected'}), 401
    data   = request.get_json(silent=True) or {}
    source = data.get('source', 'auto')
    result = start_library_sync(source=source)
    if result.get('status') == 'already_running':
        return jsonify({'status': 'already_running'})
    return jsonify({'status': 'started'})


@bp.route('/sync-status')
def sync_status():
    from .amazon_games import get_sync_state
    return jsonify(get_sync_state())


@bp.route('/uninstall/<int:appid>', methods=['POST'])
def uninstall(appid):
    from plugins.amazon_games import plugin
    result = plugin.uninstall_game(appid)
    return jsonify(result)


@bp.route('/install/<int:appid>', methods=['POST'])
def install(appid):
    from .amazon_games import start_install
    return jsonify(start_install(appid))


@bp.route('/install-status/<int:appid>')
def install_status(appid):
    from .amazon_games import get_install_state
    return jsonify(get_install_state(appid))


@bp.route('/active-install')
def active_install():
    from .amazon_games import get_active_install
    return jsonify(get_active_install())


@bp.route('/install/<int:appid>/cancel', methods=['POST'])
def install_cancel(appid):
    from .amazon_games import cancel_install
    cancel_install(appid)
    return jsonify({'status': 'ok'})


@bp.route('/rescrape/<int:appid>', methods=['POST'])
def rescrape(appid):
    from plugins.amazon_games import plugin
    from database import update_game_data
    meta = plugin.rescrape(appid)
    if meta is None:
        return jsonify({'status': 'error', 'message': 'Game not found'}), 404
    update_game_data(appid, **meta)
    return jsonify({'status': 'success', 'data': meta})


from runners.installdir import register_install_dir_routes
from .amazon_games import AMAZON_INSTALL_BASE
register_install_dir_routes(bp, 'amazon_games', AMAZON_INSTALL_BASE)
