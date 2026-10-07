#!/usr/bin/env python3
"""SpamGuard Studio: run this file, the app opens in your browser."""
import os
import sys
import time
import webbrowser

if sys.version_info < (3, 8):
    sys.exit('Python purana hai. python.org se naya Python 3 install karo.')
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sgstudio.web import Studio  # noqa: E402


def main():
    studio = Studio(home=os.environ.get('SG_HOME') or None, docs=os.environ.get('SG_DOCS') or None, no_open=bool(os.environ.get('SG_NO_OPEN')))
    try:
        url = studio.listen(int(os.environ.get('PORT') or 4780))
    except OSError as e:
        sys.exit('Start nahi ho paya: %s' % e)
    print('\n  SpamGuard Studio chal raha hai:  %s' % url)
    print('  Browser me khul jayega. Band karne ke liye is window me Ctrl+C dabao.\n')
    if not os.environ.get('SG_NO_OPEN'):
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        studio.close()


if __name__ == '__main__':
    main()
