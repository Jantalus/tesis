# SSH + tmux injection

On macOS, `TIOCSTI` ioctl is blocked (PermissionError), so writing to `/dev/ttyXXX` only pushes to output (display), not the input queue. Writing `\r` or `\n` to the tty does not commit the command.

**Correct approach: `tmux send-keys`**

1. Find the target pane:
```bash
tmux list-panes -a -F "#{session_name}:#{window_index}.#{pane_index} #{pane_pid} #{pane_current_command}"
```

2. Send a command to the pane:
```bash
tmux send-keys -t <session>:<window>.<pane> 'your command here' Enter
```

**How to identify which tty/pane owns an SSH session:**
```bash
ps aux | grep ssh          # find the tty (e.g. s018 → /dev/ttys018)
ps -t ttys018 -o pid,ppid,comm   # find parent process
ps -p <ppid> -o pid,ppid,comm    # confirm it's tmux
```

**SSH connection (two hops):**
```bash
ssh -A mgiampaolo@zorzal.dc.uba.ar       # hop 1 (jump host)
ssh -A mgiampaolo@10.1.102.74            # hop 2 (from inside zorzal)
```

The final session on `10.1.102.74` lives in the `tesis` tmux session on that machine, but the pane index should be re-discovered each session via `tmux list-panes`.
