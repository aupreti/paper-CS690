#this program compares DNS respone between US and Iran VPs
import json
import pdb
#read JSON
def readJSON(file_name):
    #load json
    with open(file_name) as centinel_result_json:
        data = json.load(centinel_result_json)
    return data

def compareDNS(irandata,usdata,compareresult):
    #pdb.set_trace()
    compareresult.write('domain, iran resolved ips,us resolved ips\n')
    iran_domains=irandata['baseline'][0]['dns']
    us_domains=usdata['baseline'][0]['dns']
    for domain in iran_domains:
        if domain in us_domains:
            #compare responses'
            compareresult.write(domain +',')
            found_iran=False
            for nameserv_block in irandata['baseline'][0]['dns'][domain]:
                if not found_iran:
                    if nameserv_block['nameserver']!='8.8.8.8':
                        if 'response1-ips' in nameserv_block:
                            compareresult.write(str(nameserv_block['response1-ips']))
                        else:
                            compareresult.write('[]')
                        found_iran=True
            if not found_iran:
                compareresult.write('[]')
            compareresult.write(',')

            if len(usdata['baseline'][0]['dns'][domain])==0:
                compareresult.write('[]')
            else:
                found= False #more than 1 local resolver
                for nameserv_block_control in usdata['baseline'][0]['dns'][domain]:
                    if not found:
                        if 'response1-ips' in nameserv_block_control:
                            compareresult.write(str(nameserv_block_control['response1-ips']))
                        else:
                            compareresult.write('[]')
                        found=True
                if not found:
                    compareresult.write('[]')
            compareresult.write('\n')

if __name__=="__main__":
    irandata=readJSON("./results/upreti_baseline-2016-12-14T190029.980291.json")
    usdata= readJSON("./results/baseline-2016-12-20T102358.858187.json")
    outputfile= "dns_comparision.csv"
    with open(outputfile, 'w') as compareresult:
        compareDNS(irandata,usdata,compareresult)
