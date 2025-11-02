# Testing Multiple Users in MLWE-PAKE Group Authentication

## How to Test with Multiple Users

The WebSocket server supports **multiple concurrent connections**, allowing you to test group authentication features with several users simultaneously.

## Method 1: Multiple Browser Tabs (Recommended)

### Step 1: Start the Server
```bash
python3 start_server.py
```

### Step 2: Open Multiple Browser Tabs
1. **Tab 1** - Open `http://localhost:8000`
2. **Tab 2** - Open `http://localhost:8000` (same URL, new tab)
3. **Tab 3** - Open `http://localhost:8000` (optional, for 3+ users)

### Step 3: Connect Each Tab as a Different User

**Tab 1:**
- User ID: `user_1`
- Click "Connect"

**Tab 2:**
- User ID: `user_2` (change from default!)
- Click "Connect"

**Tab 3:**
- User ID: `user_3` (change from default!)
- Click "Connect"

### Step 4: Join the Same Group

**In Each Tab:**
- Group ID: `group_1` (same for all!)
- Password: `test-password` (same for all!)
- Click "Join Group"

### Step 5: Observe Protocol Steps

You should see in each tab:
- Protocol steps showing when users join
- History exclusion messages when new members join (epoch increments)
- Group key establishment when 2+ members present
- Forward secrecy messages when members leave

### Step 6: Send Messages

**In any tab:**
- Type a message
- Click "Send Message"
- Message appears in **all tabs** where users are in the same group

---

## Method 2: Multiple Browser Windows

Instead of tabs, you can use separate browser windows:

1. Open `http://localhost:8000` in Chrome
2. Open `http://localhost:8000` in Firefox (or another browser)
3. Or open in Incognito/Private mode for a second window

Connect each with different User IDs.

---

## Method 3: Different Devices

If you have multiple devices on the same network:

1. Find your computer's IP address:
   ```bash
   # macOS/Linux
   ifconfig | grep "inet "
   
   # Or check in System Preferences > Network
   ```

2. Start server accessible on network:
   ```bash
   # Server already listens on 0.0.0.0, so accessible on LAN
   python3 start_server.py
   ```

3. On other device, open: `http://YOUR_IP:8000`
   - Replace `YOUR_IP` with your computer's IP address

---

## What to Observe

### When Multiple Users Join:

1. **First User Joins:**
   - Creates group
   - No epoch increment (first member)
   - Protocol step: `2_GROUP_CREATED`

2. **Second User Joins:**
   - **History Exclusion Active!**
   - Epoch increments from 0 to 1
   - Protocol step: `4_HISTORY_EXCLUDED` - shows new user cannot decrypt old messages
   - Group key established (2+ members)

3. **Third User Joins:**
   - **History Exclusion Active!**
   - Epoch increments from 1 to 2
   - New user can only decrypt from epoch 2 onwards
   - Existing members notified of epoch change

### Forward Secrecy Test:

1. User 1, User 2, User 3 all in `group_1`
2. User 2 sends a message
3. User 1 leaves group
4. **Forward Secrecy Active!**
   - Group key updated (epoch increments)
   - Protocol step: `FORWARD_SECRECY_ACTIVE`
   - User 1 cannot decrypt future messages
5. User 3 sends a message
6. User 1 (even if still "connected") cannot decrypt it

### Group Messages:

1. All users in same group
2. User 1 sends: "Hello group!"
3. **User 2 and User 3 see the message** with:
   - Sender's User ID
   - Timestamp
   - Epoch number
   - Protocol step showing ratcheting

---

## Troubleshooting

### "Connection already exists for this User ID"

**Problem:** You're trying to connect with a User ID that's already connected.

**Solution:** 
- Use a different User ID
- Or disconnect first, then reconnect
- Or use a different browser tab/window with a different User ID

### Messages Not Appearing in Other Tabs

**Check:**
1. All users are connected (green "Connected" status)
2. All users joined the **same group ID**
3. All users used the **same password**
4. Check the Messages panel for error messages
5. Check browser console (F12) for errors

### Group Key Not Established

**Requires:** At least 2 members must be in the group

**Check:**
1. At least 2 different User IDs connected
2. Both joined the same group
3. Protocol steps show `5_KEY_ESTABLISHMENT` and `6_RATCHET_INIT`

---

## Quick Test Script

Here's a quick way to test:

1. **Terminal 1:** Start server
   ```bash
   python3 start_server.py
   ```

2. **Browser Tab 1:**
   - User ID: `alice`
   - Connect → Join `group_1` with password `test123`

3. **Browser Tab 2:**
   - User ID: `bob`
   - Connect → Join `group_1` with password `test123`
   - Observe: History exclusion, epoch increment

4. **Browser Tab 3:**
   - User ID: `charlie`
   - Connect → Join `group_1` with password `test123`
   - Observe: Another epoch increment

5. **Test Messages:**
   - Alice sends: "Hello from Alice!"
   - Bob sends: "Hi Alice, this is Bob!"
   - All three should see both messages

6. **Test Forward Secrecy:**
   - Bob leaves group
   - Alice sends: "Bob left, this message is encrypted"
   - Bob should NOT see this message (forward secrecy)

---

## Dashboard Features for Multi-User Testing

- **Connected Users Count:** Shows total connected users in Connection panel
- **Protocol Steps:** Each tab shows its own protocol flow
- **Group Messages:** Messages appear in all connected tabs in the same group
- **Real-time Updates:** All tabs update in real-time

---

**Happy Testing! 🎉**

