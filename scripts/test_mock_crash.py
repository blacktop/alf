
import json
import subprocess
import time
import sys
import os

def run_test():
    print("🥒 Starting Mock Backend Test...")
    
    # Path to alf
    # Assumes we are in workspace root
    cmd = ["uv", "run", "alf", "server", "--backend", "mock", "--transport", "stdio"]
    
    print(f"Running: {' '.join(cmd)}")
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=sys.stderr,
        text=True,
        bufsize=0
    )
    
    try:
        # Helper to send request
        msg_id = 0
        def send_request(method, params=None):
            nonlocal msg_id
            msg_id += 1
            req = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "method": method,
                "params": params or {}
            }
            print(f"-> Sending {method}")
            proc.stdin.write(json.dumps(req) + "\n")
            proc.stdin.flush()
            return msg_id

        def send_notification(method, params=None):
            req = {
                "jsonrpc": "2.0",
                "method": method,
                "params": params or {}
            }
            print(f"-> Sending Notification {method}")
            proc.stdin.write(json.dumps(req) + "\n")
            proc.stdin.flush()

        # Helper to read response
        def read_response(expect_id):
            while True:
                line = proc.stdout.readline()
                if not line:
                    raise RuntimeError("Process exited unexpectedly")
                
                try:
                    msg = json.loads(line)
                    if msg.get("id") == expect_id:
                        print(f"<- Received response for {expect_id}")
                        return msg
                    if "method" in msg:
                        print(f"<- Notification: {msg['method']}")
                except json.JSONDecodeError:
                    print(f"<- Raw: {line.strip()}")

        # 1. Initialize (MCP handshake)
        rid = send_request("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "test-script", "version": "1.0"}
        })
        resp = read_response(rid)
        assert "capabilities" in resp["result"], "Missing capabilities in initialize"

        send_notification("notifications/initialized")

        # 2. List tools (verify lldb_launch exists)
        rid = send_request("tools/list")
        resp = read_response(rid)
        tools = [t["name"] for t in resp["result"]["tools"]]
        assert "lldb_launch" in tools, "lldb_launch tool missing"
        print("✓ Tools verified")

        # 3. Launch (Mock)
        rid = send_request("tools/call", {
            "name": "lldb_launch",
            "arguments": {"binary": "/bin/ls", "crash_input": "foo"}
        })
        resp = read_response(rid)
        # Verify launch result
        content = json.loads(resp["result"]["content"][0]["text"])
        print(f"Launch Result: {content}")
        assert content["status"] == "stopped", "Should be stopped (mock launch)"

        # 4. Continue (Mock Crash)
        rid = send_request("tools/call", {
            "name": "lldb_continue",
            "arguments": {"wait": True}
        })
        resp = read_response(rid)
        content = json.loads(resp["result"]["content"][0]["text"])
        print(f"Continue Result: {content}")
        assert content["reason"] == "exception", f"Expected exception, got {content.get('reason')}"
        
        # 5. Get Crash Context
        rid = send_request("resources/read", {
            "uri": "crash://current/context"
        })
        resp = read_response(rid)
        ctx = json.loads(resp["result"]["contents"][0]["text"])
        print("Crash Context keys:", ctx.keys())
        assert "backtrace" in ctx, "Missing backtrace"
        assert "registers" in ctx, "Missing registers"
        
        print("🥒 TEST PASSED: Mock backend successfully simulated a crash!")

    except Exception as e:
        print(f"❌ TEST FAILED: {e}")
        proc.terminate()
        sys.exit(1)
    finally:
        proc.terminate()

if __name__ == "__main__":
    run_test()
