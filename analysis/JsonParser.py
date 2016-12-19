#This script answers the following questions
#Verify the use of DPI by looking at HTTP path based censorship
#Breakdown Bad/Forbidden responses by categories
#Compile a list of private or forged DNS IPs that we get back
#Compile a list of name servers that give bad and good DNS response for Iran

#Where within Iran are the censoring nodes located? How many hops away from VPs?
#TODO update DPI catalog different responses, #check if DNS reply was good by comparing with google 8.8.8.8
import json
import pdb
import re
from pprint import pprint
#DPI vs control
DPI_Control_Map={"www.diigikala.com/adult":"www.diigikala.com","https://www.yahoo.com/news/politics/clit":"www.yahoo.com","http://www.blogfa.com/members/clit":"www.blogfa.com","www.blogfa.com/porn":"www.blogfa.com"}
#store results for categories in a map
categories_map={}
failed_http_websites_list=[]

#read JSON
def readJSON(file_name):
    #load json
    with open(file_name) as centinel_result_json:
        data = json.load(centinel_result_json)
    return data

def printSummarybyCategory(results):
    results.write("\n*******************************************************************")
    results.write("*** Printing percent Censorship data by Category ***\n")
    for category in categories_map:
        results.write(" %s \n"%category)
        if "tcp-connect" in categories_map[category]:
            tcp_values=categories_map[category]["tcp-connect"]
            line_tcp="%s: %f percent\n" %("TCP Connect", tcp_values.count('true')/float(len(tcp_values)) )
            results.write(line_tcp )
        if "http-connect" in categories_map[category]:
            results.write(" *** HTTP Status Codes ****\n")
            results.write(" Category, Total, 200,400, 403, 404 \n")#can add others
            http_values=categories_map[category]["http-connect"]
            line_http="%s, %d, %d, %d, %d,%d\n"%(category,len(http_values),http_values.count(200),http_values.count(400),http_values.count(403),http_values.count(404))
            results.write(line_http)
        results.write('\n List of fail messages for HTTP connect for %s \n'%category)
        results.writelines(["%s\n" % item  for item in categories_map[category]["http-connect-failures"]])
        results.write("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    results.write('\n List of failed websites for TCP connect \n')
    results.writelines(["%s, %s, %s\n" % (url,error_message, uri)  for  url, uri, error_message in failed_http_websites_list])
#compare control vs path altered with trigger word
def checkDPI(data,results):
    results.write("*** Printing results for DPI ***\n")
    results.write("*** TYPE: full path, status code, content length, server , redirect count ***\n")
    for uri in data["baseline"][0]["url_metadata"]:
        if uri in DPI_Control_Map:
            control_uri=DPI_Control_Map[uri]
            #check if response code for the two is same
            DPI_data=data["baseline"][0]["http"][uri]
            Control_data=data["baseline"][0]["http"][control_uri]
            #compare full path, status code, content length, server , redirect count
            if "redirect_count" not in DPI_data:
                redirect_count=1
            else:
                redirect_count=DPI_data["redirect_count"]
            if "redirects" in DPI_data:
                DPI_data=DPI_data["redirects"][str(len(DPI_data["redirects"])-1)]
                if "status" in DPI_data["response"]:
                    results.write("DPI: %s, %s, " %(uri,DPI_data["response"]["status"]))
                    if "Content-Length" in DPI_data["response"]["headers"]:
                        results.write("%s, %s, " %(DPI_data["response"]["headers"]["Content-Length"],DPI_data["response"]["headers"]["Server"]))
                    results.write("%s\n"%redirect_count)
            else:
                if "status" in DPI_data["response"]:
                    results.write("DPI: %s, %s, " %(uri,DPI_data["response"]["status"]))
                    if "Content-Length" in DPI_data["response"]["headers"]:
                        results.write("%s, %s, " %(DPI_data["response"]["headers"]["Content-Length"],DPI_data["response"]["headers"]["Server"]))
                    results.write("%s\n"%redirect_count)
            if "redirect_count" not in Control_data:
                redirect_count=1
            else:
                redirect_count=Control_data["redirect_count"]
            if  "redirects" in Control_data:
                Control_data=Control_data["redirects"][str(len(Control_data["redirects"])-1)]
                if "status" in Control_data["response"]:
                    results.write("Control: %s, %s, " %(control_uri,Control_data["response"]["status"]))
                    if "Content-Length" in Control_data["response"]["headers"]:
                        results.write("%s, %s, " %(Control_data["response"]["headers"]["Content-Length"],Control_data["response"]["headers"]["Server"]))
                    results.write("%s\n"%redirect_count)
            else:
                if "status" in Control_data["response"]:
                    results.write("Control: %s, %s, " %(control_uri,Control_data["response"]["status"]))
                    if "Content-Length" in Control_data["response"]["headers"]:
                        results.write("%s, %s, " %(Control_data["response"]["headers"]["Content-Length"],Control_data["response"]["headers"]["Server"]))
                    results.write("%s\n"%redirect_count)
    #check if HTTP worked 200 response
#def CheckCensoringHost():
#find IP of non-200 response

def writeSummaryStats(data,results):
    #record metadata
    results.write("COUNTRY: "+data["meta"]["country"] +"\n")
    results.write("IP: "+ data["meta"]["ip"]+"\n")
    results.write("AS NUMBER: "+data["meta"]["as_number"]+"\n");
    #baseline[0] keys--> tls,tcp_connect, http,file_name,file_metadata,file_comments,traceroute.udp,dns,total_time,url_metadata
    # check for success of TCP connect by categories
    for urlandport in data["baseline"][0]["tcp_connect"]:
        #add category to map if not present
        host=urlandport.split(":", 1)[0]
        url = [uri for uri in data["baseline"][0]["url_metadata"].keys() if re.search(host, uri)][0]
        category=data["baseline"][0]["url_metadata"][url]["category_description"]
        if "success" in data["baseline"][0]["tcp_connect"][urlandport]:
            success_or_failure='true'
        else:
            success_or_failure='false'
            #list of all failed websites
            failed_http_websites_list.append([url,uri, data["baseline"][0]["tcp_connect"][urlandport]["failure"]])
        if  category not in categories_map:
            categories_map[category]= {"tcp-connect":[success_or_failure]}
        else:
            categories_map[category]["tcp-connect"].append(success_or_failure)
    # check for  http response status by category
    for uri in data["baseline"][0]["http"]:
        all_data=data["baseline"][0]["http"][uri]
        category=data["baseline"][0]["url_metadata"][uri]["category_description"]
        #category not in map
        if category not in categories_map :
            categories_map[category]={"http-connect": [],"http-connect-failures":[]}
        #http-conect not in map but category in map
        elif "http-connect" not in categories_map[category]:
            categories_map[category]["http-connect"]=[]
            categories_map[category]["http-connect-failures"]=[]
        #redirects
        if  "redirects" in all_data:
            all_data=all_data["redirects"][str(len(all_data["redirects"])-1)]
        #response can have no status if it did not succeed
        if "failure" in all_data["response"] or "status" not in all_data["response"]:
            #a list of failure messages
            categories_map[category]["http-connect-failures"].append(all_data["response"]["failure"])
        else:
            categories_map[category]["http-connect"].append(all_data["response"]["status"])


if __name__=="__main__":
    data= readJSON('./results/upreti_baseline-2016-12-14T190029.980291.json')
    with open('centinel_results-processed', 'w') as results:
        writeSummaryStats(data,results)
        printSummarybyCategory(results)
        checkDPI(data,results)
