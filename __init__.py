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
        from .amazon_games import nile_detected, find_nile_library
        if nile_detected():
            log.info(f'Amazon Games: Nile library detected at {find_nile_library()}')

    def on_shutdown(self):
        pass

    def on_uninstall(self):
        from .amazon_games import disconnect
        disconnect()

    def launch_game(self, appid):
        from .amazon_games import launch_game
        return launch_game(appid)

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
            'uninstall_url':  None,
            'scrape_url':     '/api/amazon_games/rescrape/{appid}',
            'scrape_method':  'POST',
            'store_url':      'https://gaming.amazon.com/home',
            'store_label':    'View on Amazon Games ↗',
            'appid_label':    'Amazon Game ID:',
            'sync_label':     'Sync Amazon Library',
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
                        'redirect_pattern': 'luna.amazon.com',
                        'code_js': (
                            "(function(){"
                            # Read at-main from document.cookie (not HttpOnly for Amazon JS apps)
                            "var atMain='';"
                            "var csrf='';"
                            "var ck=document.cookie.split(';');"
                            "for(var j=0;j<ck.length;j++){"
                            "var p=ck[j].trim();"
                            "if(p.indexOf('at-main=')===0)atMain=p.slice(8);"
                            "if(p.indexOf('csrf1=')===0)csrf=p.slice(6);"
                            "if(p.indexOf('csrfToken=')===0)csrf=p.slice(10);"
                            "}"
                            "if(!atMain)return '';"
                            # Try CSRF from window variables Amazon SPAs use
                            "if(!csrf){"
                            "try{"
                            "var keys=['__anti_csrftoken_a2z','anti_csrftoken_a2z','__CSRF_TOKEN','csrfToken'];"
                            "for(var i=0;i<keys.length;i++){if(window[keys[i]]){csrf=window[keys[i]];break;}}"
                            "}catch(e){}"
                            "}"
                            # Try meta tag
                            "if(!csrf){"
                            "try{"
                            "var m=document.querySelector('meta[name=\"anti-csrftoken-a2z\"],meta[name=\"csrf-token\"]');"
                            "if(m)csrf=m.getAttribute('content')||'';"
                            "}catch(e){}"
                            "}"
                            "return JSON.stringify({token:atMain,csrf:csrf});"
                            "})()"
                        ),
                        'instructions': [
                            'The popup opens gaming.amazon.com. If you are already signed in to Amazon, '
                            'PlayDate will connect automatically.',
                            'If the popup fails to connect: sign in at gaming.amazon.com in your regular browser, '
                            'open DevTools (F12) → Application → Cookies → amazon.com, '
                            'copy the value of <code>at-main</code>, and paste it below.',
                        ],
                        'input_placeholder': 'Paste your at-main cookie value here…',
                        'open_label': 'Open Amazon Games',
                        'submit_label': 'Connect',
                    }},
                    {'type': 'button', 'label': 'Paste at-main manually', 'variant': 'muted', 'action': {
                        'type': 'oauth_paste',
                        'title': 'Connect Amazon Games',
                        'url_endpoint': '/api/amazon_games/auth-url',
                        'callback_endpoint': '/api/amazon_games/connect',
                        'instructions': [],
                        'input_placeholder': '',
                        'open_label': '',
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

        return {'sections': sections}

    def fragments(self):
        return {
            'tools_scripts': 'amazon_games_tools_scripts.html',
        }


plugin = AmazonGamesPlugin()
