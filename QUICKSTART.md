# Quick Start Guide - MLWE-PAKE Project

## 🚀 Quick Start (Recommended: WebSocket Dashboard)

This is the easiest way to run the project with the full group authentication features.

### Step 1: Install Dependencies

```bash
# Make sure you're in the project directory
cd /Users/tejshreesuresh/Documents/GitHub/mlwe-pake

# Install Python dependencies
# On macOS/Linux, use pip3 if pip doesn't work:
pip3 install -r requirements.txt

# Or try:
python3 -m pip install -r requirements.txt
```

### Step 2: Start the WebSocket Server

```bash
# Option A: Using the start script (easiest)
python3 start_server.py

# Option B: Using uvicorn directly
python3 -m uvicorn websocket_server:app --host 0.0.0.0 --port 8000 --reload
```

You should see:
```
============================================================
MLWE-PAKE Group Authentication Server
============================================================

Starting server on http://localhost:8000
Access the dashboard at: http://localhost:8000

Press Ctrl+C to stop the server
============================================================
```

### Step 3: Access the Dashboard

Open your web browser and navigate to:
```
http://localhost:8000
```

### Step 4: Use the Dashboard

1. **Connect**: Enter a User ID (e.g., `user_1`) and click "Connect"
2. **Join Group**: Enter a Group ID (e.g., `group_1`) and password, then click "Join Group"
3. **View Protocol Steps**: All protocol steps with timestamps will appear in the Messages panel
4. **Test Features**:
   - Join with multiple users (open multiple browser tabs/windows)
   - Observe forward secrecy when members leave
   - Observe history exclusion when new members join
   - View real-time performance metrics

---

## 🔧 Alternative: Traditional 1-to-1 PAKE

For testing the original socket-based PAKE protocol:

### Step 1: Start the Server

**Terminal 1:**
```bash
python pake_server.py
```

The server will output a base64-encoded public key. **Copy this key!**

### Step 2: Update Client with Server Key

Edit `pake_client.py` and replace the `SERVER_PK_B64` variable with the public key from Step 1.

### Step 3: Run the Client

**Terminal 2:**
```bash
python pake_client.py
```

---

## 📋 Prerequisites Checklist

Before running, ensure you have:

- ✅ **Python 3.9+** installed
- ✅ **liboqs-python** installed (check with `python3 -c "import oqs; print(oqs.oqs_version())"`)
- ✅ **All Python dependencies** installed (`pip install -r requirements.txt`)

### Verify liboqs-python Installation

```bash
python3 -c "import oqs; print('liboqs-python version:', oqs.oqs_version())"
```

If this fails, see the README.md Installation section for detailed setup instructions.

---

## 🐛 Troubleshooting

### Error: "ModuleNotFoundError: No module named 'oqs'"

**Solution**: Install liboqs-python bindings:
```bash
cd liboqs-python
python3 -m build
pip install dist/*.whl
cd ..
```

### Error: "Address already in use"

**Solution**: Port 8000 is already in use. Either:
- Stop the other process using port 8000
- Use a different port: `uvicorn websocket_server:app --port 8001`

### Error: "Failed to join group"

**Solution**: 
- Make sure the WebSocket connection is established (click "Connect" first)
- Check that you've entered a Group ID
- Look at the protocol steps in the Messages panel for detailed error info

### Dashboard Not Loading

**Solution**:
- Check that the server started successfully
- Verify `templates/index.html` and `static/` files exist
- Check browser console for JavaScript errors (F12)

---

## 📚 What You'll See

### WebSocket Dashboard Features

1. **Connection Panel**: Connect/disconnect from WebSocket
2. **Performance Metrics Panel**: Real-time crypto operation statistics
3. **Group Management Panel**: Join/leave groups
4. **Messages Panel**: 
   - Protocol steps with timestamps
   - Group messages
   - Error messages
   - All color-coded for easy reading

### Protocol Steps You'll See

When joining a group:
- `1_VALIDATION` - Validating join request
- `2_GROUP_CREATED` - Group creation (if new)
- `3_MEMBER_ADD` - Adding member to group
- `4_HISTORY_EXCLUDED` - History exclusion active
- `5_KEY_ESTABLISHMENT` - Group key derivation
- `6_RATCHET_INIT` - Double ratchet initialization
- `7_JOIN_COMPLETE` - Join successful

When leaving a group:
- `1_LEAVE_INIT` - Leave process started
- `2_KEY_UPDATE` - Key updated for forward secrecy
- `FORWARD_SECRECY_ACTIVE` - Forward secrecy notification
- `3_LEAVE_COMPLETE` - Leave successful

All steps include timestamps with millisecond precision!

---

## 🔄 Running Multiple Instances

To test group features with multiple users:

1. Start the server once: `python start_server.py`
2. Open multiple browser tabs/windows
3. Connect each tab with a different User ID (e.g., `user_1`, `user_2`, `user_3`)
4. Join the same group with the same password
5. Observe protocol steps in each tab

---

## 🛑 Stopping the Server

Press `Ctrl+C` in the terminal where the server is running.

---

## 📖 Next Steps

- Read `README.md` for detailed architecture and features
- Read `FEATURE_CONFIRMATION.md` for feature verification
- Check `GROUP_FEATURES_README.md` for group-specific documentation
- Run tests: `python test_mlwe_pake.py`

---

**Happy Testing! 🎉**
