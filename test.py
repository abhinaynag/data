import re, sys , os , string

fh= open('splunk_raw_log','r')
#sig =" * "+"\n * ".join(list(set(re.findall("snort:\s\[1:\d+:\d+\].*{\w+}",fh.read()))))
#sip =' , '.join(set(re.findall("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", ','.join(re.findall("\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+\s->)",fh.read())))))
#xfwd=' , '.join(re.findall("(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",repr(set(re.findall("(\d{2}\/\d{2}\/\d{2,4})\s(\d{2}:\d{2}:\d{2})\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",fh.read())))))
#sport=string.replace(', '.join(set(re.findall(":\d+\s" , repr(re.findall("\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+\s->)",fh.read()))))),":","")
#dip= ' , '.join(set(re.findall("(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",repr(re.findall("->\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+",fh.read())))))
#dport=string.replace(' , '.join(set(re.findall(":\d+" , repr(re.findall("->\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+)",fh.read()))))),":","")

print dport
