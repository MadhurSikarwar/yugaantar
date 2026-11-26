"""Child stops at an explicit durable step; parent terminates it externally."""
import sys
import time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from t4.crypto import sig
from t4.node.common import open_log
from t4.node.authority import Authority
from t4.node.device import Device

root=Path(sys.argv[1]); step=sys.argv[2]
def fault(reached):
    if reached==step:
        (root/'reached').write_text(reached)
        while True: time.sleep(.1)

Device(root/'device',sig).rotate(Authority(root/'authority',sig,open_log(root/'authority/log')),
                               101,114,fault)
