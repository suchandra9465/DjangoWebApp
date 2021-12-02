
import re

def ss (instr):
    
    outstr = re.sub ('%20',' ',instr)
    outstr = re.sub ('%2b','_',outstr)
    
    return outstr; 