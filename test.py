import re, sys , os , string

fh= open('raw','r')
data=fh.read()

print "\n \n ******* Start of Output  **************"
#sig =" * "+"\n * ".join(set(re.findall("(snort:\s\[1:\d+:\d+\].*:\s\d{1}\])",data)))
#sig =list((set(re.findall("((snort:\s\[1:\d+:\d+\](\s\w+)+(\s\((\w+\W?)+\))?(\s\[Classification:(\s\w+)+\])(\s\[Priority:\s\d{1}\])\s{\w{3}}))",data))))
tmp= repr(list(set(re.findall("((snort:\s\[1:\d+:\d+\](\s\w+)+(\s\((\w+\W?)+\))?(\s\[Classification:(\s\w+)+\])(\s\[Priority:\s\d{1}\])\s{\w{3}}))",data))))
for item in tmp:

#sip =' , '.join(set(re.findall("(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", ','.join(re.findall("\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+)\s->",data)))))
#xfwd=' , '.join(re.findall("(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",repr(set(re.findall("(\d{2}\/\d{2}\/\d{2,4})\s+(\d{2}:\d{2}:\d{2})\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",data)))))
#sport=string.replace(', '.join(set(re.findall(":\d+\s" , repr(re.findall("\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+\s->)",data))))),":","")
#dip= ' , '.join(set(re.findall("(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",repr(re.findall("->\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+",data)))))
#dport=string.replace(' , '.join(set(re.findall(":\d+" , repr(re.findall("->\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+)",data))))),":","")
fh.close()
print sig
#print sig+"\n"+sip+"\n"+xfwd+"\n"+sport+"\n"+dip+"\n"+dport

