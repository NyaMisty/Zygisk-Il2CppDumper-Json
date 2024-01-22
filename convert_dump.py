#!/usr/bin/env python
# coding: utf-8

with open('dump.cs') as f:
    testData = f.read()

import re

methods = []
for m in re.finditer(r'''(?m)// Dll : .*?
// Namespace: (.*?)(?:|\n\[.*?\])
.*?(?:class|enum) ([^\s]+?)(?:\s|\s.*?\s){
	// Fields
([\S\s]*?)
	// Properties
([\S\s]*?)
	// Methods
([\S\s]*?)}

''', testData):
    ns, cls, field, prop, meth = m.groups()
    meth_count = meth.count('	// RVA')
    meth_parsed = re.findall(r'''(?m)	// RVA: (0x.*?) VA: (0x.*?)
	.* (.*?)\(.*\) \{ ''', meth)
    #print(meth_count, meth_parsed)
    assert len(meth_parsed) == meth_count
    for rva, va, methName in meth_parsed:
        if rva == '0x':
            # failed func
            continue
        methods.append({
          "Address": int(rva, 0),
          "Name": "%s$$%s" % (cls, methName),
          "Signature": None,
        })
    #print(ns, cls, meth_count, meth_parsed)

with open('methods.json', 'w') as f:
    import json
    json.dump({'ScriptMethod': methods}, f)
