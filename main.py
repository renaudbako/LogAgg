#!/usr/bin/env python3
"""
LogAgg — Real-time log aggregation and anomaly detection.

Usage:
    python main.py [--host HOST] [--port PORT] [--db PATH] [--debug]
"""
import argparse
import logging
import platform
import signal
import sys


def _setup_logging(debug: bool):
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def _parse_args():
    p = argparse.ArgumentParser(description="LogAgg – real-time log aggregator")
    p.add_argument("--host",  default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    p.add_argument("--port",  type=int, default=5000, help="HTTP port (default: 5000)")
    p.add_argument("--db",    default="logagg.db", help="SQLite DB path")
    p.add_argument("--debug", action="store_true", help="Enable debug mode")
    return p.parse_args()


def main():
    args = _parse_args()
    _setup_logging(args.debug)
    log = logging.getLogger("logagg")

    from config import Config
    config = Config(
        host=args.host,
        port=args.port,
        db_path=args.db,
        debug=args.debug,
    )

    log.info("Starting LogAgg on %s:%d  [%s]", args.host, args.port,
             platform.system())
    log.info("Database: %s", args.db)

    from web.app import create_app
    app, socketio = create_app(config)

    # Graceful shutdown
    def _shutdown(sig, frame):
        log.info("Shutting down …")
        if hasattr(app, '_tailer'):
            app._tailer.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    print(f"\n  LogAgg  →  http://{args.host}:{args.port}\n")

    socketio.run(
        app,
        host=args.host,
        port=args.port,
        debug=args.debug,
        use_reloader=False,
        log_output=args.debug,
    )


if __name__ == "__main__":
    main()
