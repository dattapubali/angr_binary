import angr
import datetime
from angrutils import *

#proj = angr.Project("angr-utils/examples/samples/ais3_crackme", load_options={'auto_load_libs':False})
proj = angr.Project("a.out", load_options={'auto_load_libs':False})
main = proj.loader.main_bin.get_symbol("main")
start_state = proj.factory.blank_state(addr=main.addr)
starttime = datetime.datetime.now()
cfg = proj.analyses.CFGAccurate(fail_fast=True, starts=[main.addr], initial_state=start_state)
endtime = datetime.datetime.now()
print "CFG construction completed"
exectime = endtime - starttime
plot_cfg(cfg, "thttpd_cfg", asminst=True, remove_imports=True, remove_path_terminator=True)
print exectime
