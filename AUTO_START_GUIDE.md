# Telfin Agent Auto-Start Guide

This guide explains how to set up the Telfin agent to start automatically when your system boots.

## Quick Start

```bash
# 1. Authenticate with Telfin
telfin login

# 2. Install the auto-start service
telfin install

# That's it! The agent will now start automatically on boot
```

## Platform-Specific Details

### Linux (systemd)

#### What Gets Installed:
- Service file: `~/.config/systemd/user/telfin-agent.service`
- Runs as a user service (no root required)
- Automatically restarts on failure
- Starts on boot (with lingering enabled)

#### Management Commands:
```bash
# Start the service now
systemctl --user start telfin-agent

# Stop the service
systemctl --user stop telfin-agent

# Check service status
systemctl --user status telfin-agent

# View live logs
journalctl --user -u telfin-agent -f

# View recent logs
journalctl --user -u telfin-agent -n 100

# Restart the service
systemctl --user restart telfin-agent
```

#### Manual Installation:
If you prefer to install manually, create `~/.config/systemd/user/telfin-agent.service`:

```ini
[Unit]
Description=Telfin SSH Tunnel Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/telfin start
Restart=always
RestartSec=10

[Install]
WantedBy=default.target
```

Then run:
```bash
systemctl --user daemon-reload
systemctl --user enable telfin-agent
systemctl --user start telfin-agent
loginctl enable-linger $USER
```

### macOS (launchd)

#### What Gets Installed:
- Plist file: `~/Library/LaunchAgents/io.telfin.agent.plist`
- Runs on user login
- Automatically restarts if it exits
- Logs to: `~/Library/Application Support/telfin/agent.log`

#### Management Commands:
```bash
# Stop the service
launchctl unload ~/Library/LaunchAgents/io.telfin.agent.plist

# Start the service
launchctl load ~/Library/LaunchAgents/io.telfin.agent.plist

# View logs (live)
tail -f ~/Library/Application\ Support/telfin/agent.log

# View recent logs
tail -100 ~/Library/Application\ Support/telfin/agent.log

# Check if service is loaded
launchctl list | grep telfin
```

#### Manual Installation:
Create `~/Library/LaunchAgents/io.telfin.agent.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>io.telfin.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/telfin</string>
        <string>start</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/tmp/telfin-agent.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/telfin-agent.log</string>
</dict>
</plist>
```

Then run:
```bash
launchctl load ~/Library/LaunchAgents/io.telfin.agent.plist
```

### Windows (Task Scheduler)

#### What Gets Installed:
- Scheduled task: `TelfinAgent`
- Runs on user login
- Runs with highest privileges
- Auto-restarts if the system reboots

#### Management Commands:
```powershell
# Start the task now
schtasks /run /tn TelfinAgent

# Stop the running agent
taskkill /f /im telfin.exe

# Check task status
schtasks /query /tn TelfinAgent

# View task details
schtasks /query /tn TelfinAgent /v /fo list
```

#### Manual Installation:
```powershell
schtasks /create /tn "TelfinAgent" /tr "C:\path\to\telfin.exe start" /sc onlogon /rl highest /f
```

Or use Task Scheduler GUI:
1. Open Task Scheduler
2. Create Basic Task
3. Name: `TelfinAgent`
4. Trigger: "When I log on"
5. Action: Start a program
6. Program: `C:\path\to\telfin.exe`
7. Arguments: `start`
8. Properties > Run with highest privileges

## Uninstalling Auto-Start

To remove the auto-start service:

```bash
telfin uninstall
```

This will:
- Stop the running service/task
- Remove all service files
- Clean up configuration

You can reinstall at any time with `telfin install`.

## Troubleshooting

### Linux: Service won't start on boot

Make sure lingering is enabled:
```bash
loginctl enable-linger $USER
loginctl show-user $USER | grep Linger
```

Should show `Linger=yes`. If not, run:
```bash
loginctl enable-linger $USER
```

### macOS: Service not starting

Check if the plist is loaded:
```bash
launchctl list | grep telfin
```

If not loaded, manually load it:
```bash
launchctl load ~/Library/LaunchAgents/io.telfin.agent.plist
```

Check logs for errors:
```bash
tail -50 ~/Library/Application\ Support/telfin/agent.log
```

### Windows: Task not running

Check task status:
```powershell
schtasks /query /tn TelfinAgent
```

Make sure you're logged in (task runs on logon).

Check Windows Event Viewer for errors:
```
Event Viewer > Windows Logs > Application
```

Filter for "Task Scheduler" events.

### General: Agent starts but can't connect

Check if you're logged in:
```bash
telfin status
```

If not logged in, authenticate:
```bash
telfin login
```

Check network connectivity to gateway:
```bash
# Linux/macOS
curl -I https://gateway.telfin.io

# Windows
Invoke-WebRequest -Uri https://gateway.telfin.io -Method Head
```

## Environment Variables

The service respects these environment variables:

- `RUST_LOG` - Set log level (default: info)
  - Values: trace, debug, info, warn, error
- `TELFIN_SERVER` - Override server URL (default: https://gateway.telfin.io)

### Setting Environment Variables:

**Linux (systemd)**: Edit service file and add:
```ini
[Service]
Environment="RUST_LOG=debug"
Environment="TELFIN_SERVER=https://custom.server.com"
```

**macOS (launchd)**: Edit plist and add:
```xml
<key>EnvironmentVariables</key>
<dict>
    <key>RUST_LOG</key>
    <string>debug</string>
    <key>TELFIN_SERVER</key>
    <string>https://custom.server.com</string>
</dict>
```

**Windows**: Set system environment variables or add to task action:
```powershell
setx RUST_LOG "debug"
setx TELFIN_SERVER "https://custom.server.com"
```

## Security Considerations

- The service runs with your user privileges (not root)
- Credentials are stored in system keychain:
  - Linux: Secret Service (GNOME Keyring, KWallet)
  - macOS: Keychain
  - Windows: Credential Manager
- No network ports are opened locally
- All connections are outbound to the Telfin gateway

## Advanced Configuration

You can customize the agent behavior by editing the config file:

**Config Location**:
- Linux: `~/.config/telfin/config.json`
- macOS: `~/Library/Application Support/telfin/config.json`
- Windows: `%APPDATA%\telfin\config.json`

**Example config.json**:
```json
{
  "server_url": "https://gateway.telfin.io",
  "machine_name": "my-laptop",
  "reconnect_interval": 5,
  "heartbeat_interval": 30,
  "log_level": "info",
  "shell_command": null
}
```

**Configuration Options**:
- `server_url`: Gateway server URL
- `machine_name`: Display name for this machine
- `reconnect_interval`: Seconds between reconnect attempts (1-60)
- `heartbeat_interval`: Seconds between heartbeats (5-300)
- `log_level`: Logging verbosity (trace, debug, info, warn, error)
- `shell_command`: Custom shell to use (default: $SHELL or /bin/bash)

After editing, restart the service for changes to take effect.

## Support

If you encounter issues:

1. Check the logs (see platform-specific sections above)
2. Verify you're logged in: `telfin status`
3. Test manual start: `telfin start` (see if it works without service)
4. Check network connectivity
5. Review configuration file

For bug reports, include:
- Platform and version
- Service status/logs
- Output of `telfin status`
- Any error messages
