#!/bin/bash
# (b) Daemon logs are private: initial files, then a FORCED newsyslog rotation, then a second user.
# Run as dev on the VM (sudo -n is non-interactive; dev is admin). Expects axtest2 to exist.
set -u
D=/Library/Logs/Axiom; C=/etc/newsyslog.d/com.axiom.service.conf
echo "# (b) daemon log privacy"; date -u
echo '$ cat '$C; cat $C
echo '$ sudo -n stat -f "%Sp %Su:%Sg %z %N" '$D' '$D'/*'
sudo -n sh -c "stat -f '%Sp %Su:%Sg %z %N' $D $D/*"
echo '$ sudo -n newsyslog -F -v -f '$C
sudo -n newsyslog -F -v -f $C 2>&1; echo "rc=$?"
sleep 2
echo '$ sudo -n launchctl kickstart system/com.axiom.service is NOT run; the daemon reopens on its own write'
echo '$ sudo -n stat (after forced rotation)'
sudo -n sh -c "stat -f '%Sp %Su:%Sg %z %N' $D $D/*"
echo '$ non-root admin dev: ls / cat'
ls -l $D 2>&1 | head -3; cat $D/axiomd.log 2>&1 | head -1
for f in $(sudo -n sh -c "ls $D"); do
  echo "\$ sudo -n -u axtest2 cat $D/$f"; sudo -n -u axtest2 cat "$D/$f" 2>&1 | head -1 | cut -c1-120
done
echo '$ sudo -n -u axtest2 ls -l '$D; sudo -n -u axtest2 ls -l $D 2>&1 | head -2
echo '$ trigger a daemon log line (serviceHealth over IPC) and re-check the live file'
python3 -c 'import sys; sys.path.insert(0,"/tmp/axsec"); from seclib import call; print(call("serviceHealth")["ok"])'
sleep 1; sudo -n sh -c "stat -f '%Sp %Su:%Sg %z %N' $D $D/*"
