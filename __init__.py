import logging

log = logging.getLogger(__name__)


class AmazonGamesPlugin:
    id       = 'amazon_games'
    name     = 'Amazon Games'
    platform = 'amazon_games'
    label    = 'Amazon Games'

    def register(self, app):
        from .routes import bp
        app.register_blueprint(bp)
        log.info('Amazon Games plugin registered')

    def on_startup(self):
        from .amazon_games import nile_detected, find_nile_library, resync_installed
        if nile_detected():
            log.info(f'Amazon Games: Nile library detected at {find_nile_library()}')
        try:
            resync_installed()
        except Exception as e:
            log.warning(f'Amazon Games resync_installed at startup failed: {e}')

    def on_shutdown(self):
        pass

    def on_uninstall(self):
        from .amazon_games import disconnect
        disconnect()

    def launch_game(self, appid):
        from .amazon_games import launch_game
        return launch_game(appid)

    def uninstall_game(self, appid):
        from .amazon_games import uninstall_game
        return uninstall_game(appid)

    def resync_installed(self):
        from .amazon_games import resync_installed
        resync_installed()

    def rescrape(self, appid):
        from datetime import date
        from database import get_db
        from .amazon_games import _fetch_art
        db  = get_db()
        row = db.execute("SELECT name FROM games WHERE appid = ?", (appid,)).fetchone()
        db.close()
        if not row:
            return None
        today = date.today().isoformat()
        _fetch_art(appid, row['name'])
        return {'meta_fetched': today}

    def fetch_description(self, appid, platform_id):
        return None

    def js_api(self):
        return {
            'uninstall_url':     '/api/amazon_games/uninstall/{appid}',
            'uninstall_confirm': 'Uninstall this game and delete its files?',
            'scrape_url':        '/api/amazon_games/rescrape/{appid}',
            'scrape_method':     'POST',
            'store_url':         'https://gaming.amazon.com/home',
            'store_label':       'View on Amazon Games ↗',
            'appid_label':       'Amazon Game ID:',
            'sync_label':        'Sync Amazon Library',
            'install_poller':    'amazonInstallPoll',
        }

    def manage_ui(self):
        from .amazon_games import nile_detected
        nile = nile_detected()

        sections = []

        if nile:
            sections.append({
                'title': 'Heroic / Nile',
                'items': [
                    {
                        'type': 'text',
                        'content': (
                            'Nile library detected from Heroic Games Launcher. '
                            'Sync will import your library directly from local files — no login needed.'
                        ),
                    },
                    {'type': 'button', 'label': 'Sync Library', 'action': {'type': 'call', 'fn': 'amazonGamesSync'}},
                    {'type': 'status_output', 'key': 'main'},
                ],
            })

        sections.append({
            'title': 'Amazon Account' if not nile else 'Amazon Account (Alternative)',
            'auth': {
                'endpoint': '/api/amazon_games/status',
                'disconnected': [
                    {'type': 'text', 'content': 'Connect your Amazon account to import your library.'},
                    {'type': 'button', 'label': 'Connect Amazon Account', 'action': {
                        'type': 'oauth_popup',
                        'title': 'Connect Amazon Games',
                        'url_endpoint': '/api/amazon_games/auth-url',
                        'callback_endpoint': '/api/amazon_games/connect',
                        # amazon.com/ap/signin (no www) redirects here on success with
                        # openid.oa2.authorization_code in the query string --
                        # deliberately checked for by name (not just "landed on
                        # www.amazon.com") so this can't fire on an incidental visit to
                        # the amazon.com homepage before login actually completes.
                        'redirect_pattern': 'www.amazon.com',
                        'code_js': (
                            "window.location.href.indexOf('openid.oa2.authorization_code')>=0 "
                            "? window.location.href : ''"
                        ),
                        'instructions': [
                            'Click <strong>Open Amazon Login</strong> and sign in to your Amazon account.',
                            'The window closes itself once sign-in completes.',
                            'If it gets stuck: sign in at '
                            '<a href="https://www.amazon.com" target="_blank">amazon.com</a> in your regular '
                            'browser first, then click Open again.',
                        ],
                        'open_label': 'Open Amazon Login',
                        'submit_label': 'Connect',
                    }},
                ] if not nile else [
                    {
                        'type': 'text',
                        'content': 'Already using Nile above. Optionally connect via Amazon API for a fresh library fetch.',
                    },
                ],
                'connected': [
                    {'type': 'connected_label'},
                    {'type': 'buttons', 'items': [
                        {'label': 'Sync Library',
                         'action': {'type': 'call', 'fn': 'amazonGamesSync'}},
                        {'label': 'Disconnect', 'variant': 'muted',
                         'action': {'type': 'post', 'endpoint': '/api/amazon_games/disconnect',
                                    'on_success': 'refresh_auth'}},
                    ]},
                    {'type': 'status_output', 'key': 'main'},
                ],
            },
        })

        sections.append({
            'title': 'Games Folder',
            'items': [
                {'type': 'text', 'content': 'Where PlayDate installs Amazon games.'},
                {'type': 'info_endpoint', 'endpoint': '/api/amazon_games/games-dir-info'},
                {'type': 'buttons', 'items': [
                    {'label': 'Set Folder…', 'action': {'type': 'call', 'fn': 'amazonGamesPickFolder'}},
                    {'label': 'Open Folder', 'action': {'type': 'call', 'fn': 'amazonGamesOpenFolder'}},
                ]},
                {'type': 'status_output', 'key': 'folder'},
            ],
        })

        return {'sections': sections}

    def fragments(self):
        return {
            'base_head_styles':  'amazon_games_base_head_styles.html',
            'base_nav_items':    'amazon_games_base_nav_items.html',
            'base_body_scripts': 'amazon_games_base_scripts.html',
            'tools_scripts':     'amazon_games_tools_scripts.html',
        }


plugin = AmazonGamesPlugin()
