import os,requests, base64, json,time,csv
from datetime import datetime
class Function:
   def __init__(self, id_C, secret_C):
      self.id_C = id_C
      self.secret_C = secret_C
      self.token=''
   def displayToken(self):
     print ("Token : " + self.token)
   def Authentication(self) :
        data_string =self.id_C+':'+self.secret_C
        data_bytes = data_string.encode("utf-8")
        encoded = base64.b64encode(data_bytes).decode('utf-8')
        url = "https://api.labs.sophos.com/oauth2/token"
        payload = "grant_type=client_credentials"
        headers = {
        'Authorization': "Basic " + encoded,
        'Content-Type': "application/x-www-form-urlencoded",
        'Host': "api.labs.sophos.com",
        }
        response1 = requests.request("POST", url, data=payload, headers=headers)
        if(response1.status_code == 200 ):
           resultToken=json.loads(response1.text)
           self.token = resultToken["access_token"]
           return self.token;
        else:
           return "Invalid_client";
   def getFileByHash(self,sha256,token):
      url1 = "https://de.api.labs.sophos.com/lookup/files/v1/"+sha256
      headers1 = {
          'Authorization': token,
          'Host': "de.api.labs.sophos.com",
      }
      response1 = requests.request("GET", url1, headers=headers1)
      if(response1.status_code == 200 ):
            response=json.loads(response1.text)
            dt_string = datetime.now()
            dayNow = dt_string.strftime("%m_%Y")
            if(os.path.isfile('reportCsv/IntelixReport_'+dayNow+'.csv')!=True):
                   with open('reportCsv/IntelixReport_'+dayNow+'.csv', 'w', newline='') as csvfile:
                        fieldnames = ['Date', 'Sha256', 'Type_Request']
                        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                        writer.writeheader()
                        dayNowTime=dt_string.strftime("%d_%m_%Y")
                        writer.writerow({'Date': dayNowTime, 'Sha256': sha256, 'Type_Request': 'getFileByHash'})
            else:
                 dayNowTime=dt_string.strftime("%d_%m_%Y")
                 valeurs =[dayNowTime,sha256,"getFileByHash"]
                 with open('reportCsv/IntelixReport_'+dayNow+'.csv', 'a') as csvfile:
                       writer = csv.writer(csvfile)
                       writer.writerow(valeurs)
                 
            a=response["reputationScore"]
            if a>=0 and a<=19:
              print("Malware");
              if("detectionName" in response):
                 print("DetectionName : "+response["detectionName"]);
            elif a>=20 and a<=29:
              print("PUA");
              if("detectionName" in response):
                 print("DetectionName : "+response["detectionName"]);
            elif a>=30 and a<=69:
              print("Unknown/suspicious");
              if("detectionName" in response):
                 print("DetectionName : "+response["detectionName"]);
            elif a>=70 and a<=100:
              print("Known good");
              if("detectionName" in response):
                 print("DetectionName : "+response["detectionName"]);
            else :
              print(" Not found");
      elif(response1.status_code == 401 ):
           print ("Token has expired")
      elif(response1.status_code == 404 ):
            response=json.loads(response1.text)
            print(response["error"])
      else:
           print ("Your token has already been expired or it's not for this service.")
   def scanURL(self,url,token):
      url1 = "https://de.api.labs.sophos.com/lookup/urls/v1/"+url
      headers1 = {
          'Authorization': token,
          'Host': "de.api.labs.sophos.com",
      }
      response1 = requests.request("GET", url1, headers=headers1)
      if(response1.status_code == 200) :
            response=json.loads(response1.text)
            p=response["productivityCategory"]
            p=response["productivityCategory"]
            r=response["riskLevel"]
            dt_string = datetime.now()
            dayNow = dt_string.strftime("%m_%Y")
            if(os.path.isfile('reportCsv/IntelixReport_URL_'+dayNow+'.csv')!=True):
                   with open('reportCsv/IntelixReport_URL_'+dayNow+'.csv', 'w', newline='') as csvfile:
                        fieldnames = ['Date', 'URL', 'Type_Request']
                        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                        writer.writeheader()
                        dayNowTime=dt_string.strftime("%d_%m_%Y")
                        writer.writerow({'Date': dayNowTime, 'URL': url, 'Type_Request': 'scanURL'})
            else:
                   dayNowTime=dt_string.strftime("%d_%m_%Y")
                   valeurs =[dayNowTime, url, "scanURL"]
                   with open('reportCsv/IntelixReport_URL_'+dayNow+'.csv', 'a') as csvfile:
                       writer = csv.writer(csvfile)
                       writer.writerow(valeurs)
            print("Category of Productivity : "+p)
            print("Risk : "+r)
            if ("securityCategory" in response):
               c=response["securityCategory"]
               print("Category of Securite : "+c)
      elif(response1.status_code == 401 ):
              print ("Token has expired")
      elif(response1.status_code == 404 ):
               print ("The requested URL does not exist")
      else:
              print ("Your token has already been expired or it's not for this service.")
   def scanAPK(self,apk,token):
      url1 = "https://de.api.labs.sophos.com/lookup/apk/v1/"+apk
      headers1 = {
          'Authorization': token,
          'Host': "de.api.labs.sophos.com",
      }
      response1 = requests.request("GET", url1, headers=headers1)
      if(response1.status_code == 200 ):
            response=json.loads(response1.text)
            dt_string = datetime.now()
            dayNow = dt_string.strftime("%m_%Y")
            if(os.path.isfile('reportCsv/IntelixReport_Android_'+dayNow+'.csv')!=True):
                   with open('reportCsv/IntelixReport_Android_'+dayNow+'.csv', 'w', newline='') as csvfile:
                        fieldnames = ['Date', 'APK', 'Type_Request']
                        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                        writer.writeheader()
                        dayNowTime=dt_string.strftime("%d_%m_%Y")
                        writer.writerow({'Date': dayNowTime, 'APK': apk, 'Type_Request': 'scanAPK'})
            else:
                   dayNowTime=dt_string.strftime("%d_%m_%Y")
                   valeurs =[dayNowTime, apk, "scanAPK"]
                   with open('reportCsv/IntelixReport_Android_'+dayNow+'.csv', 'a') as csvfile:
                       writer = csv.writer(csvfile)
                       writer.writerow(valeurs)
            a=response["reputationScore"]
            if a>=0 and a<=19:
              print("Malware");
              if("detectionName" in response):
                 print("DetectionName : "+response["detectionName"]);
            elif a>=20 and a<=29:
              print("PUA");
              if("detectionName" in response):
                 print("DetectionName : "+response["detectionName"]);
            elif a>=30 and a<=69:
              print("Unknown/suspicious");
              if("detectionName" in response):
                 print("DetectionName : "+response["detectionName"]);
            elif a>=70 and a<=100:
              print("Known good");
              if("detectionName" in response):
                 print("DetectionName : "+response["detectionName"]);
            else :
              print(" Not found");
      elif(response1.status_code == 401 ):
           print("Token has expired");
      elif(response1.status_code == 404 ):
            response=json.loads(response1.text)
            print(response["error"]);
      else:
           print ("Your token has already been expired or it's not for this service.")
   def scanAPKPackage(self,apk,token,package):
      url1 = "https://de.api.labs.sophos.com/lookup/apk/v1/"+apk+"/"+package
      headers1 = {
          'Authorization': token,
          'Host': "de.api.labs.sophos.com",
      }
      response1 = requests.request("GET", url1, headers=headers1)
      if(response1.status_code == 200 ):
            response=json.loads(response1.text)
            dt_string = datetime.now()
            dayNow = dt_string.strftime("%m_%Y")
            if(os.path.isfile('reportCsv/IntelixReport_Android_'+dayNow+'.csv')!=True):
                   with open('reportCsv/IntelixReport_Android_'+dayNow+'.csv', 'w', newline='') as csvfile:
                        fieldnames = ['Date', 'APK', 'Type_Request']
                        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                        writer.writeheader()
                        dayNowTime=dt_string.strftime("%d_%m_%Y")
                        writer.writerow({'Date': dayNowTime, 'APK': apk, 'Type_Request': 'scanAPKPackage'})
            else:
                   dayNowTime=dt_string.strftime("%d_%m_%Y")
                   valeurs =[dayNowTime, apk, "scanAPKPackage"]
                   with open('reportCsv/IntelixReport_Android_'+dayNow+'.csv', 'a') as csvfile:
                       writer = csv.writer(csvfile)
                       writer.writerow(valeurs)
            a=response["reputationScore"]
            if a>=0 and a<=19:
              print("Malware");
              if("detectionName" in response):
                 print("DetectionName : "+response["detectionName"]);
            elif a>=20 and a<=29:
              print("PUA");
              if("detectionName" in response):
                 print("DetectionName : "+response["detectionName"]);
            elif a>=30 and a<=69:
              print("Unknown/suspicious");
              if("detectionName" in response):
                 print("DetectionName : "+response["detectionName"]);
            elif a>=70 and a<=100:
              print("Known good");
              if("detectionName" in response):
                 print("DetectionName : "+response["detectionName"]);
            else :
              print(" Not found");
      elif(response1.status_code == 401 ):
           print("Token has expired");
      elif(response1.status_code == 404 ):
            response=json.loads(response1.text)
            print(response["error"]);
      else:
           print ("Your token has already been expired or it's not for this service.")
   def scanFileStatic(self,file,token):
        url = "https://de.api.labs.sophos.com/analysis/file/static/v1"
        headers = {'Authorization': token}
        response1 = requests.post(url, headers=headers, files={"file": open(file, "rb")})
        if(response1.status_code == 200 ):
            response=json.loads(response1.text)
            t=True
            r=response
            fichier = open('static/'+response['report']['analysis_subject']['sha256']+".json", "w")
            fichier.write(json.dumps(r, indent=4, sort_keys=True))
            fichier.close()
            dt_string = datetime.now()
            dayNow = dt_string.strftime("%m_%Y")
            if(os.path.isfile('reportCsv/IntelixReport_'+dayNow+'.csv')!=True):
                   with open('reportCsv/IntelixReport_'+dayNow+'.csv', 'w', newline='') as csvfile:
                        fieldnames = ['Date', 'Sha256', 'Type_Request']
                        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                        writer.writeheader()
                        dayNowTime=dt_string.strftime("%d_%m_%Y")
                        writer.writerow({'Date': dayNowTime, 'Sha256': response['report']['analysis_subject']['sha256'], 'Type_Request': 'Static'})
            else:
                   dayNowTime=dt_string.strftime("%d_%m_%Y")
                   valeurs =[dayNowTime,response['report']['analysis_subject']['sha256'] ,"Static"]
                   with open('reportCsv/IntelixReport_'+dayNow+'.csv', 'a') as csvfile:
                       writer = csv.writer(csvfile)
                       writer.writerow(valeurs)
            return t,r
        elif(response1.status_code == 202 ):
            response=json.loads(response1.text)
            t=False
            r=response["jobId"]
            return t,r
        elif(response1.status_code == 400 ):
            response=json.loads(response1.text)
            t=True
            r=response
            return t,r
        elif(response1.status_code == 401 ):
            print ("Token has expired")
            t=True
            r="Token has expired"
            return t,r
        elif(response1.status_code == 404 ):
            response=json.loads(response1.text)
            r=response
            t=True
            return t,r
        elif(response1.status_code == 405 ):
            response=json.loads(response1.text)
            t=True
            r=response["error"]
            return t,r
        else:
            response=json.loads(response1.text)
            r=response["error"]
            t=True
            return t,r
   def scanFileStaticJobID(self,jobid,token):
        url = "https://de.api.labs.sophos.com/analysis/file/static/v1/reports/"+jobid
        headers = {'Authorization': token}
        response1 = requests.get(url, headers=headers)
        if(response1.status_code == 200 ):
            response=json.loads(response1.text)
            t=True
            r=response
            fichier = open('static/'+response['report']['analysis_subject']['sha256']+".json", "w")
            fichier.write(json.dumps(r, indent=4, sort_keys=True))
            fichier.close()
            dt_string = datetime.now()
            dayNow = dt_string.strftime("%m_%Y")
            if(os.path.isfile('reportCsv/IntelixReport_'+dayNow+'.csv')!=True):
                   with open('reportCsv/IntelixReport_'+dayNow+'.csv', 'w', newline='') as csvfile:
                        fieldnames = ['Date', 'Sha256', 'Type_Request']
                        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                        writer.writeheader()
                        dayNowTime=dt_string.strftime("%d_%m_%Y")
                        writer.writerow({'Date': dayNowTime, 'Sha256': response['report']['analysis_subject']['sha256'], 'Type_Request': 'StaticJobID'})
            else:
                   dayNowTime=dt_string.strftime("%d_%m_%Y")
                   valeurs =[dayNowTime,response['report']['analysis_subject']['sha256'] ,"StaticJobID"]
                   with open('reportCsv/IntelixReport_'+dayNow+'.csv', 'a') as csvfile:
                       writer = csv.writer(csvfile)
                       writer.writerow(valeurs)
            return t,r
        elif(response1.status_code == 202 ):
            r=jobid
            t=False
            return t,r
        elif(response1.status_code == 400 ):
            response=json.loads(response1.text)
            r=response
            t=True
            return t,r
        elif(response1.status_code == 401 ):
            t=True
            r="Token has expired"
            return t,r
        elif(response1.status_code == 404 ):
            response=json.loads(response1.text)
            t=True
            r=response
            return t,r
        elif(response1.status_code == 405 ):
            response=json.loads(response1.text)
            t=True
            r=response
            return t,r
        else:
            response=json.loads(response1.text)
            t=True
            r=response
            return t,r
   def reportFileStatic(self,sha,token):
        url = "https://de.api.labs.sophos.com/analysis/file/static/v1/reports"
        querystring = {"sha256":sha}
        headers = {'Authorization': token}
        response1 = requests.request("GET", url, headers=headers, params=querystring)
        if(response1.status_code == 200 ):
            response=json.loads(response1.text)
            fichier = open('static/'+response['report']['analysis_subject']['sha256']+".json", "w")
            fichier.write(json.dumps(response, indent=4, sort_keys=True))
            fichier.close()
            dt_string = datetime.now()
            dayNow = dt_string.strftime("%m_%Y")
            if(os.path.isfile('reportCsv/IntelixReport_'+dayNow+'.csv')!=True):
                   with open('reportCsv/IntelixReport_'+dayNow+'.csv', 'w', newline='') as csvfile:
                        fieldnames = ['Date', 'Sha256', 'Type_Request']
                        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                        writer.writeheader()
                        dayNowTime=dt_string.strftime("%d_%m_%Y")
                        writer.writerow({'Date': dayNowTime, 'Sha256': response['report']['analysis_subject']['sha256'], 'Type_Request': 'reportFileStatic'})
            else:
                   dayNowTime=dt_string.strftime("%d_%m_%Y")
                   valeurs =[dayNowTime,response['report']['analysis_subject']['sha256'] ,"reportFileStatic"]
                   with open('reportCsv/IntelixReport_'+dayNow+'.csv', 'a') as csvfile:
                       writer = csv.writer(csvfile)
                       writer.writerow(valeurs)
        elif(response1.status_code == 400 ):
            response=json.loads(response1.text)
            print(response["error"])
        elif(response1.status_code == 401 ):
            print ("Token has expired")
        elif(response1.status_code == 404 ):
            response=json.loads(response1.text)
            print(response["error"])
        elif(response1.status_code == 405 ):
            response=json.loads(response1.text)
            print(response["error"])
        else:
            response=json.loads(response1.text)
            print(response["error"])
   def scanFileDynamic(self,file,token):
        url = "https://de.api.labs.sophos.com/analysis/file/dynamic/v1"
        headers = {'Authorization': token}
        response1 = requests.post(url, headers=headers, files={"file": open(file, "rb")})
        if(response1.status_code == 200 ):
            response=json.loads(response1.text)
            t=True
            r=response
            fichier = open('dynamic/'+response['report']['analysis_subject']['sha256']+".json", "w")
            fichier.write(json.dumps(r, indent=4, sort_keys=True))
            fichier.close()
            dt_string = datetime.now()
            dayNow = dt_string.strftime("%m_%Y")
            if(os.path.isfile('reportCsv/IntelixReport_'+dayNow+'.csv')!=True):
                   with open('reportCsv/IntelixReport_'+dayNow+'.csv', 'w', newline='') as csvfile:
                        fieldnames = ['Date', 'Sha256', 'Type_Request']
                        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                        writer.writeheader()
                        dayNowTime=dt_string.strftime("%d_%m_%Y")
                        writer.writerow({'Date': dayNowTime, 'Sha256': response['report']['analysis_subject']['sha256'], 'Type_Request': 'scanFileDynamic'})
            else:
                   dayNowTime=dt_string.strftime("%d_%m_%Y")
                   valeurs =[dayNowTime,response['report']['analysis_subject']['sha256'] ,"scanFileDynamic"]
                   with open('reportCsv/IntelixReport_'+dayNow+'.csv', 'a') as csvfile:
                       writer = csv.writer(csvfile)
                       writer.writerow(valeurs)
            return t,r
        elif(response1.status_code == 202 ):
            response=json.loads(response1.text)
            t=False
            r=response["jobId"]
            return t,r
        elif(response1.status_code == 400 ):
            response=json.loads(response1.text)
            t=True
            r=response
            return t,r
        elif(response1.status_code == 401 ):
            print ("Token has expired")
            t=True
            r="Token has expired"
            return t,r
        elif(response1.status_code == 404 ):
            response=json.loads(response1.text)
            r=response
            t=True
            return t,r
        elif(response1.status_code == 405 ):
            response=json.loads(response1.text)
            t=True
            r=response["error"]
            return t,r
        else:
            response=json.loads(response1.text)
            r=response["error"]
            t=True
            return t,r

   def scanFileDynamicJobID(self,jobid,token):
        url = "https://de.api.labs.sophos.com/analysis/file/dynamic/v1/reports/"+jobid
        headers = {'Authorization': token}
        response1 = requests.get(url, headers=headers)
        if(response1.status_code == 200 ):
            response=json.loads(response1.text)
            t=True
            r=response
            fichier = open('dynamic/'+response['report']['analysis_subject']['sha256']+".json", "w")                         
            fichier.write(json.dumps(response, indent=4, sort_keys=True))
            fichier.close()
            dt_string = datetime.now()
            dayNow = dt_string.strftime("%m_%Y")
            if(os.path.isfile('reportCsv/IntelixReport_'+dayNow+'.csv')!=True):
                   with open('reportCsv/IntelixReport_'+dayNow+'.csv', 'w', newline='') as csvfile:
                        fieldnames = ['Date', 'Sha256', 'Type_Request']
                        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                        writer.writeheader()
                        dayNowTime=dt_string.strftime("%d_%m_%Y")
                        writer.writerow({'Date': dayNowTime, 'Sha256': response['report']['analysis_subject']['sha256'], 'Type_Request': 'scanFileDynamicJobID'})
            else:
                   dayNowTime=dt_string.strftime("%d_%m_%Y")
                   valeurs =[dayNowTime,response['report']['analysis_subject']['sha256'] ,"scanFileDynamicJobID"]
                   with open('reportCsv/IntelixReport_'+dayNow+'.csv', 'a') as csvfile:
                       writer = csv.writer(csvfile)
                       writer.writerow(valeurs)
            return t,r
        elif(response1.status_code == 202 ):
            r=jobid
            t=False
            return t,r
        elif(response1.status_code == 400 ):
            response=json.loads(response1.text)
            r=response
            t=True
            return t,r
        elif(response1.status_code == 401 ):
            t=True
            r="Token has expired"
            return t,r
        elif(response1.status_code == 404 ):
            response=json.loads(response1.text)
            t=True
            r=response
            return t,r
        elif(response1.status_code == 405 ):
            response=json.loads(response1.text)
            t=True
            r=response
            return t,r
        else:
            response=json.loads(response1.text)
            t=True
            r=response
            return t,r
   def reportFileDynamic(self,sha,token):
        url = "https://de.api.labs.sophos.com/analysis/file/dynamic/v1/reports"
        querystring = {"sha256":sha}
        headers = {'Authorization': token}
        response1 = requests.request("GET", url, headers=headers, params=querystring)
        if(response1.status_code == 200 ):
            response=json.loads(response1.text)
            fichier = open('dynamic/'+response['report']['analysis_subject']['sha256']+".json", "w")                    
            fichier.write(json.dumps(response, indent=4, sort_keys=True))
            fichier.close()
            dt_string = datetime.now()
            dayNow = dt_string.strftime("%m_%Y")
            if(os.path.isfile('reportCsv/IntelixReport_'+dayNow+'.csv')!=True):
                   with open('reportCsv/IntelixReport_'+dayNow+'.csv', 'w', newline='') as csvfile:
                        fieldnames = ['Date', 'Sha256', 'Type_Request']
                        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                        writer.writeheader()
                        dayNowTime=dt_string.strftime("%d_%m_%Y")
                        writer.writerow({'Date': dayNowTime, 'Sha256':response['report']['analysis_subject']['sha256'], 'Type_Request': 'reportFileDynamic'})
            else:
                 dayNowTime=dt_string.strftime("%d_%m_%Y")
                 valeurs =[dayNowTime,response['report']['analysis_subject']['sha256'] ,"reportFileDynamic"]
                 with open('reportCsv/IntelixReport_'+dayNow+'.csv', 'a') as csvfile:
                       writer = csv.writer(csvfile)
                       writer.writerow(valeurs)
        elif(response1.status_code == 400 ):
            response=json.loads(response1.text)
            print(response["error"])
        elif(response1.status_code == 401 ):
            print ("Token has expired")
        elif(response1.status_code == 404 ):
            response=json.loads(response1.text)
            print(response["error"])
        elif(response1.status_code == 405 ):
            response=json.loads(response1.text)
            print(response["error"])
        else:
            response=json.loads(response1.text)
            print(response["error"])

   def searchSha256FileStatic(self,sha256,token):
      test=False
      for element in os.listdir('static'):
         if (os.path.splitext(element)[0]==sha256):
            print("Sha256 Exists")
            fichier = open('static/'+sha256+".json", "rb")
            t= json.load(fichier)
            fichier.close()
            test=True
            return test,t
         else:
               test=False ;
      if (test == False):
            t="Sha256 doesn't exist"
            return test,t
   def searchSha256FileDynamic(self,sha256,token):
      test=False
      for element in os.listdir('dynamic'):
         if (os.path.splitext(element)[0]==sha256):
            print("Sha256 Exists")
            fichier = open('dynamic/'+sha256+".json", "r")
            t= json.load(fichier)
            fichier.close()
            test=True
            return test,t
         else:
               test=False ;
      if (test == False):
            t="Sha256 doesn't exist"
            return test,t
