import ssl, socket
import time

S=""
def tup2str(tup):
    global S
    def tt(a):
        global S
        for i in a:
            if str(type(i[0]))=="<class 'str'>":
                if len(i)==1:
                    S+=i[0]+"; "
                elif len(i)==2:
                    S=S+i[0]+"="+i[1]+"; "
                else:
                    S+=str(i)+"; "
            elif str(type(i))=="<class 'tuple'>":
                tt(i)
            else:
                S+=str(i)
    S=""
    tt(tup)
    print(S)
    return S

def check(domain):
    item={}
    try:
        item["domain"] = domain
        c = ssl.create_default_context()
        s = c.wrap_socket(socket.socket(), server_hostname=item["domain"])
        s.connect((item["domain"], 443))
        cert = s.getpeercert()
        #print(cert)

        item["check"]=time.ctime(time.time())
        nowstamp=time.mktime(time.strptime(time.ctime(time.time()),"%a %b %d %H:%M:%S %Y"))
        expirestamp=time.mktime(time.strptime(cert['notAfter'],"%b %d %H:%M:%S %Y GMT"))
        item["remain"]=int((expirestamp-nowstamp)/86400)

        if expirestamp<nowstamp:
            item["status"]="Expired"
            item["statuscolor"]="error"
        elif item["remain"]<10 and item["remain"]>=0:
            item["status"]="Soon Expired"
            item["statuscolor"]="warning"
        elif item["remain"]>=10:
            item["status"]="Valid"
            item["statuscolor"]="success"
        else:
            item["status"]="Invalid"
            item["statuscolor"]="error"

        for i in cert:
            if str(type(cert[i]))=="<class 'tuple'>":
                item[i]=tup2str(cert[i])
            else:
                item[i]=str(cert[i])
    
            
    except:
        item["version"]="Invalid"
        item["serialNumber"]="Invalid"
        item["subjectAltName"]="Invalid"
        item["OCSP"]="Invalid"
        item["caIssuers"]="Invalid"
        item["subject"]="Invalid"
        item['notBefore']="Invalid"
        item['notAfter']="Invalid"
        item["issuer"]="Invalid"
        item["remain"]="0"
        item["check"]=time.ctime(time.time())
        item["status"]="Invalid"
        item["statuscolor"]="error"
    return item

def listToJson(lst):
    import json
    str_json = json.dumps(lst)  # json转为string
    return str_json

f = open("./domains", "rb")
File = f.read().decode("utf8","ignore")
f.close()
Lines = File.splitlines()
result=[]
for i in Lines:
    if i:
        print(i)
        result.append(check(i))


f = open("./public/ct.json", "w",encoding="utf-8")
print(listToJson(result),file = f)
f.close()
