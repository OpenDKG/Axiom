#!/bin/bash
# (b2) Log continuity after a FORCED newsyslog rotation (fix for the check (b) finding), plus privacy.
# Run as dev on the VM from the directory holding seclib.py (sudo -n is non-interactive; dev is
# admin). Expects axtest2 (standard user) to exist for the second-user reads.
set -u
D=/Library/Logs/Axiom; C=/etc/newsyslog.d/com.axiom.service.conf; P=/var/run/axiomd.pid
st() { sudo -n sh -c "stat -f '%Sp %Su:%Sg %z %i %N' $D $D/*"; }
fds() { sudo -n lsof -p "$1" 2>/dev/null | awk 'NR==1 || /axiomd\.log/'; }
mark() { python3 - "$1" <<'PY'
import sys; sys.path.insert(0, ".")
from seclib import RID, apply_block, remove, show
rid = RID.format(0xb2)
show("apply (" + sys.argv[1] + ")", apply_block(rid, "sec-b2"))
show("remove (" + sys.argv[1] + ")", remove(rid))
PY
}
echo "# (b2) daemon log continuity across newsyslog rotation"; date -u
echo '$ cat '$C; cat $C
PID=$(sudo -n launchctl print system/com.axiom.service | awk '/^\tpid = /{print $3}')
echo "daemon pid (launchctl) $PID"
echo '$ ls -l '$P' ; cat '$P; ls -l $P; cat $P
echo '$ before: stat (mode owner size inode name)'; st
echo '$ before: axiomd fds on axiomd.log'; fds "$PID"
mark "before rotation"; sleep 1
echo '$ stat after the marker writes'; st
echo '$ sudo -n newsyslog -F -v -f '$C
sudo -n newsyslog -F -v -f $C 2>&1; echo "rc=$?"
sleep 3
echo '$ after rotation: stat'; st
echo '$ after rotation: axiomd fds on axiomd.log (expect the NEW inode)'; fds "$PID"
mark "after rotation"; sleep 1
echo '$ after the marker writes: stat (expect axiomd.log to grow, .0.bz2 unchanged)'; st
echo '$ sudo -n tail -n 8 '$D'/axiomd.log'; sudo -n tail -n 8 $D/axiomd.log | cut -c1-160
echo '$ same daemon pid?'; sudo -n launchctl print system/com.axiom.service | awk '/^\tpid = /{print "pid", $3}'
echo '$ non-root admin dev: ls / cat'
ls -l $D 2>&1 | head -2; cat $D/axiomd.log 2>&1 | head -1
for f in $(sudo -n sh -c "ls $D"); do
  echo "\$ sudo -n -u axtest2 cat $D/$f"; sudo -n -u axtest2 cat "$D/$f" 2>&1 | head -1 | cut -c1-120
done
echo '$ sudo -n -u axtest2 ls -l '$D; sudo -n -u axtest2 ls -l $D 2>&1 | head -2
echo '$ id axtest2; dseditgroup -o checkmember -m axtest2 admin'; id axtest2; dseditgroup -o checkmember -m axtest2 admin
