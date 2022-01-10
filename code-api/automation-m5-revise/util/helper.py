import os
import re


def file_to_list(filename):
    file_list = []
    if os.path.isfile(filename):
        with open(filename, 'r') as infile:
            for line in infile:
                if line[0] != '#':
                    file_list.append(line)

    return file_list


def sc(instr):
    out_str = re.sub('%20', ' ', instr)
    out_str = re.sub('%2b', '_', out_str)
    return re.sub(r'[]`/,?!@#$%^&*()<>;:=+{}\\\[\"\']', '_', out_str)


def ss(instr):
    out_str = re.sub('%20', ' ', instr)
    return re.sub('%2b', '_', out_str)
