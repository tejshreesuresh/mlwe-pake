#!/usr/bin/env python3
"""
Quick start script for MLWE-PAKE WebSocket Server
"""

import uvicorn
import sys

if __name__ == "__main__":
    print("=" * 60)
    print("MLWE-PAKE Group Authentication Server")
    print("=" * 60)
    print("\nStarting server on http://localhost:8000")
    print("Access the dashboard at: http://localhost:8000")
    print("\nPress Ctrl+C to stop the server")
    print("=" * 60 + "\n")
    
    try:
        uvicorn.run(
            "websocket_server:app",
            host="0.0.0.0",
            port=8000,
            reload=True,  # Auto-reload on code changes
            log_level="info"
        )
    except KeyboardInterrupt:
        print("\n\nServer stopped.")
        sys.exit(0)

