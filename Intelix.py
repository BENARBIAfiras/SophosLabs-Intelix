import argparse, os,base64,requests, json,time
from function import Function
from pprint import pprint
SLIntelixLIntelix=Function("","")
t=""
# Python 3

def main(): 
    global SLIntelix
    global t 
    """SophosLabs API Authentication"""
    Client_Id = "<INSERT_Client_Id_HERE>"
    Client_Secret="<INSERT_Client_Secret_HERE>"
    SLIntelix=Function(Client_Id,Client_Secret)
    t=SLIntelix.Authentication()
    fichier = open("token.txt", "w")
    fichier.write(t)
    fichier.close()
    parser = argparse.ArgumentParser(description = "Test de SophosLabs Intelix !")
    # defining arguments for parser object 
    parser.add_argument("-u", "--url", type = str, nargs = 1, default = None, help = "The URL encoded URL to look up . URL " )   
    parser.add_argument("-r", "--sha256", type = str, nargs = 1, default = None, help = "SophosLabs File Malware Cloud Lookup API (EAP). Hash function !") 
    parser.add_argument("-apk", "--android", type = str, nargs = 1,help = "SophosLabs Android Malware App Lookup API (EAP). APK")
    parser.add_argument("-apkpac", "--androidPackage", type = str, nargs = 2,help = "SophosLabs Android Malware App Lookup API (EAP). APK Package")
    parser.add_argument("-s", "--static", type = str, nargs = 1,help = "SophosLabs Static File Analysis API (EAP).  File Path !")
    parser.add_argument("-reports", "--staticReport", type = str, nargs = 1,help = "SophosLabs Static File Analysis API (EAP).  Sha256 !") 
    parser.add_argument("-d", "--dynamic", type = str, nargs = 1,help = "SophosLabs Dynamic File Analysis API (EAP). File Path !")   
    parser.add_argument("-reportd ", "--dynamicReport", type = str, nargs = 1,help = "SophosLabs Dynamic File Analysis API (EAP). Sha256 !")

    # parse the arguments from standard input 
    args = parser.parse_args() 

    #SophosLabs Malware and Productivity URL Lookup API (EAP)
    if args.url :
        fi=args.url[0]
        fichier = open("token.txt", "r")
        t= fichier.readlines()
        if (t[0]=="Invalid_client"):
                t=SLIntelix.Authentication()
                fichier = open("token.txt", "w")
                fichier.write(t)
                fichier.close()
                fichier = open("token.txt", "r")
                t= fichier.readlines()
        fichier.close()
        SLIntelix.scanURL(fi,t[0])
    #SophosLabs File Malware Cloud Lookup API (EAP)
    elif args.sha256 :
            h=args.sha256[0]
            fichier = open("token.txt", "r")
            t= fichier.readlines()
            fichier.close()
            if (t[0]=="Invalid_client"):
                    t=SLIntelix.Authentication()
                    fichier = open("token.txt", "w")
                    fichier.write(t)
                    fichier.close()
                    t= fichier.readlines()
                    fichier.close()
            SLIntelix.getFileByHash(h,t[0])          
    #SophosLabs Android Malware App Lookup API (EAP)       
    elif args.android: 
        apk=args.android[0]
        fichier = open("token.txt", "r")
        t= fichier.readlines()
        if (t[0]=="Invalid_client"):
                t=SLIntelix.Authentication()
                fichier = open("token.txt", "w")
                fichier.write(t)
                fichier.close()
                fichier = open("token.txt", "r")
                t= fichier.readlines()
        fichier.close()
        SLIntelix.scanAPK(apk,t[0]) 
    elif args.androidPackage :
        apk=args.androidPackage[0]
        pack=args.androidPackage[1]
        fichier = open("token.txt", "r")
        t= fichier.readlines()
        if (t[0]=="Invalid_client"):
                t=SLIntelix.Authentication()
                fichier = open("token.txt", "w")
                fichier.write(t)
                fichier.close()
                fichier = open("token.txt", "r")
                t= fichier.readlines()
        fichier.close()
        SLIntelix.scanAPKPackage(apk,t[0],pack) 
    #SophosLabs Static File Analysis API (EAP)
    elif args.static : 
        file=args.static[0]
        fichier = open("token.txt", "r")
        t= fichier.readlines()
        if (t[0]=="Invalid_client"):
                t=SLIntelix.Authentication()
                fichier = open("token.txt", "w")
                fichier.write(t)
                fichier.close()
                fichier = open("token.txt", "r")
                t= fichier.readlines()
        fichier.close()
        te,jobID=SLIntelix.scanFileStatic(file,t[0])
        if(te==False):
            print("IN_PROGRESS")
            fichier = open("token.txt", "r")
            t= fichier.readlines()
            if (t[0]=="Invalid_client"):
                t=SLIntelix.Authentication()
                fichier = open("token.txt", "w")
                fichier.write(t)
                fichier.close()
                fichier = open("token.txt", "r")
                t= fichier.readlines()
            fichier.close()
            time.sleep(15)
            a,r=SLIntelix.scanFileStaticJobID(jobID,t[0])
            c=0
            while((a==False)and(c < 180)):
                fichier = open("token.txt", "r")
                t= fichier.readlines()
                if (t[0]=="Invalid_client"):
                    t=SLIntelix.Authentication()
                    fichier = open("token.txt", "w")
                    fichier.write(t)
                    fichier.close()
                    fichier = open("token.txt", "r")
                    t= fichier.readlines()
                fichier.close()
                time.sleep(5)
                a,r=SLIntelix.scanFileStaticJobID(jobID,t[0])
                print("IN_PROGRESS")
                c=c+1
            if((a==True) and (c <= 179) ):
                 print("Done")
            else:
                 print("Time Out!!")                  
        else :
            print ("Done")
    elif args.staticReport : 
        sha=args.staticReport[0]
        fichier = open("token.txt", "r")
        t= fichier.readlines()
        if (t[0]=="Invalid_client"):
                t=SLIntelix.Authentication()
                fichier = open("token.txt", "w")
                fichier.write(t)
                fichier.close()
                fichier = open("token.txt", "r")
                t= fichier.readlines()
        fichier.close()
        test,res=SLIntelix.searchSha256FileStatic(sha,t[0])
        if(test==False):
            print("File Not Exist  ")
            fichier = open("token.txt", "r")
            t= fichier.readlines()
            if (t[0]=="Invalid_client"):
                t=SLIntelix.Authentication()
                fichier = open("token.txt", "w")
                fichier.write(t)
                fichier.close()
                fichier = open("token.txt", "r")
                t= fichier.readlines()
            fichier.close()
            SLIntelix.reportFileStatic(sha,t[0])
        else:
            print(json.dumps(res, indent=4))
    #SophosLabs Dynamic File Analysis API (EAP)
    elif args.dynamic : 
        file=args.dynamic[0]
        fichier = open("token.txt", "r")
        t= fichier.readlines()
        if (t[0]=="Invalid_client"):
                t=SLIntelix.Authentication()
                fichier = open("token.txt", "w")
                fichier.write(t)
                fichier.close()
                fichier = open("token.txt", "r")
                t= fichier.readlines()
        fichier.close()
        te,jobID=SLIntelix.scanFileDynamic(file,t[0])
        if(te==False):
            print("IN_PROGRESS")
            fichier = open("token.txt", "r")
            t= fichier.readlines()
            if (t[0]=="Invalid_client"):
                t=SLIntelix.Authentication()
                fichier = open("token.txt", "w")
                fichier.write(t)
                fichier.close()
                fichier = open("token.txt", "r")
                t= fichier.readlines()
            fichier.close()
            time.sleep(15)
            a,r=SLIntelix.scanFileDynamicJobID(jobID,t[0])
            c=0
            while((a==False)and(c < 60)):
                fichier = open("token.txt", "r")
                t= fichier.readlines()
                if (t[0]=="Invalid_client"):
                    t=SLIntelix.Authentication()
                    fichier = open("token.txt", "w")
                    fichier.write(t)
                    fichier.close()
                    fichier = open("token.txt", "r")
                    t= fichier.readlines()
                fichier.close()
                time.sleep(15)
                a,r=SLIntelix.scanFileDynamicJobID(jobID,t[0])
                print("IN_PROGRESS")
                c=c+1
            if((a==True) and (c <=60) ):
                  print("Done")
            else:
                  print("Time Out!!")
                  
        else :
                   print("Done")
    elif (args.dynamicReport):
        sha=args.dynamicReport[0]
        fichier = open("token.txt", "r")
        t= fichier.readlines()
        if (t[0]=="Invalid_client"):
                t=SLIntelix.Authentication()
                fichier = open("token.txt", "w")
                fichier.write(t)
                fichier.close()
                fichier = open("token.txt", "r")
                t= fichier.readlines()
        fichier.close()
        test,res=SLIntelix.searchSha256FileDynamic(sha,t[0])
        if(test==False):
            print("File Not Exist ")
            fichier = open("token.txt", "r")
            t= fichier.readlines()
            if (t[0]=="Invalid_client"):
                t=SLIntelix.Authentication()
                fichier = open("token.txt", "w")
                fichier.write(t)
                fichier.close()
                fichier = open("token.txt", "r")
                t= fichier.readlines()
            fichier.close()
            SLIntelix.reportFileDynamic(sha,t[0])
        else:
            print(json.dumps(res, indent=4))
        
if __name__ == "__main__": 
    main()
