"""Bounded ordinary-signal-resistant cleanup helpers, no execution at import."""
from contextlib import contextmanager
import signal
import threading

SIGNALS = (signal.SIGINT,signal.SIGTERM,signal.SIGHUP)

@contextmanager
def ordinary_signals_ignored():
    # Python owns process signal handlers on its main thread only. API worker
    # threads still execute cleanup, with process signal ownership retained by
    # the independent workflow supervisor. No handler install or restoration.
    if threading.current_thread() is not threading.main_thread():
        yield
        return
    previous={sig:signal.signal(sig,signal.SIG_IGN) for sig in SIGNALS}
    try:yield
    finally:
        for sig,handler in previous.items():signal.signal(sig,handler)


def attempt(errors,stage,action):
    try:return action()
    except BaseException as e:
        errors.append({'stage':stage,'class':type(e).__name__,'detail':str(e)[:512]})
        return None


def error_record(error):
    return None if error is None else {'class':type(error).__name__,'detail':str(error)[:512]}
