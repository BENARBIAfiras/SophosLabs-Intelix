# SophosLabs-Intelix
In order to use the basic functionability of API SophosLabs Intelix , we have developped a tool that allows static or dynamical analysis of files . In other words , the latter servers to examine and to identify malicious for Android Applications . It consists of scanning 
hash or file giving a Json file that includes the analysis results.


# Authors  : 
    -Script Author: BEN ARBIA Firas
    -Supervisor : BEN ABDALLAH Walid

# Resources : 
    -SophosLabs Intelix :
          .https://api.labs.sophos.com/doc/index.html
          .https://www.sophos.com/en-us/medialibrary/PDFs/factsheets/sophoslabs-intelix-ds.pdf?cmp=35051
    -AWS Marketplace : https://aws.amazon.com/marketplace/pp/B07SLZPMCS
    

# Example  : 

    SophosLabs-Intelix >Intelix.py -h
    usage: test.py [-h] 
                   [-u URL]
                   [-r Sha256]
                   [-apk ANDROID]
                   [-apkpac ANDROIDPACKAGE ANDROIDPACKAGE]
                   [-s STATIC]
                   [-reports STATICREPORT]
                   [-d DYNAMIC]
                   [-reportd  DYNAMICREPORT]
                  
    Test de SophosLabs Intelix !

    optional arguments:
      -h, --help            show this help message and exit
      -u URL, --url URL     The URL encoded URL to look up . URL
      -r Sha256, --sha256 Sha256          SophosLabs File Malware Cloud Lookup API (EAP). Hash function !
      -apk ANDROID, --android ANDROID
                            SophosLabs Android Malware App Lookup API (EAP). APK
      -apkpac ANDROIDPACKAGE ANDROIDPACKAGE, --androidPackage ANDROIDPACKAGE ANDROIDPACKAGE
                            SophosLabs Android Malware App Lookup API (EAP). APK Package
      -s STATIC, --static STATIC
                            SophosLabs Static File Analysis API (EAP). File Path !
       -reports STATICREPORT, --staticReport STATICREPORT
                        SophosLabs Static File Analysis API (EAP). Sha256 !
       -d DYNAMIC, --dynamic DYNAMIC
                        SophosLabs Dynamic File Analysis API (EAP). File Path
                        !
       -reportd  DYNAMICREPORT, --dynamicReport DYNAMICREPORT
                        SophosLabs Dynamic File Analysis API (EAP). Sha256 !
      
# Example SophosLabs Malware and Productivity URL Lookup API :
        
        SophosLabs-Intelix > Intelix.py -u sophostest.com%2Fmalware
        Category of Productivity : PROD_SPYWARE_AND_MALWARE
        Risk : HIGH
        Category of Securite : SEC_MALWARE_REPOSITORY
      
# Example SophosLabs File Malware Cloud Lookup API :
        
        SophosLabs-Intelix >Intelix.py -r d70a85f3ef7494f85a6bf35e60c666c8e2335563c7ad7e6d8ae69f058173ce2b
        Malware
        DetectionName : Mal/Generic-S

# Example SophosLabs Static File Analysis API :
      
        SophosLabs-Intelix >Intelix.py -s fichier.doc 
          Done
          
        SophosLabs-Intelix >Intelix.py -reports 7472cfa6308f8f4712a63d9e44bbbfbb0e7cc8f03ec3a787dcb783d578ea3713
          Sha256 Exists
          {
              "jobId": "649e729e83d8bb06292bc50bb4139156",
              "jobStatus": "SUCCESS",
              "report": {
                  "analysis_subject": {
                      "mime_type": "application/octet-stream",
                      "sha1": "90039b8aa31096b542560ebacefb3dcecad02380",
                      "sha256": "7472cfa6308f8f4712a63d9e44bbbfbb0e7cc8f03ec3a787dcb783d578ea3713"
                  },
                  "analysis_summary": [
                      {
                          "description": "Document may contain the CVE-2017-11882 exploit",
                          "markcount": 0,
                          "marks": [],
                          "name": "edr_cve_2017_11882",
                          "severity": 3
                      },
                      {
                          "description": "Document contains embedded Equation objects",
                          "markcount": 0,
                          "marks": [],
                          "name": "edr_embedded_equation_object",
                          "severity": 2
                      },
                      {
                          "description": "Document has obfuscated RTF header",
                          "markcount": 0,
                          "marks": [],
                          "name": "edr_obfuscated_header",
                          "severity": 2
                      },
                      {
                          "description": "Document contains automatically activated object",
                          "markcount": 0,
                          "marks": [],
                          "name": "edr_suspicious_controlword_autoupdate",
                          "severity": 2
                      },
                      {
                          "description": "Document contains appended data",
                          "markcount": 1,
                          "marks": [
                              {
                                  "category": "appended-size",
                                  "extra_info": null,
                                  "ioc": 1,
                                  "type": "ioc"
                              }
                          ],
                          "name": "edr_appended_data",
                          "severity": 1
                      },
                      {
                          "description": "Document file size is small",
                          "markcount": 1,
                          "marks": [
                              {
                                  "category": "meta_data",
                                  "extra_info": null,
                                  "ioc": "3488",
                                  "type": "ioc"
                              }
                          ],
                          "name": "edr_info_file_size_small",
                          "severity": 1
                      },
                      {
                          "description": "Document contains embedded object",
                          "markcount": 1,
                          "marks": [
                              {
                                  "category": "object-info",
                                  "extra_info": null,
                                  "ioc": "Type: equation; size: 1627",
                                  "type": "ioc"
                              }
                          ],
                          "name": "edr_info_object",
                          "severity": 1
                      },
                      {
                          "description": "Document has missing metadata fields",
                          "markcount": 10,
                          "marks": [
                              {
                                  "category": "meta_data",
                                  "extra_info": null,
                                  "ioc": "Missing META data field: codepage",
                                  "type": "ioc"
                              },
                              {
                                  "category": "meta_data",
                                  "extra_info": null,
                                  "ioc": "Missing META data field: create_time",
                                  "type": "ioc"
                              },
                              {
                                  "category": "meta_data",
                                  "extra_info": null,
                                  "ioc": "Missing META data field: last_saved_time",
                                  "type": "ioc"
                              },
                              {
                                  "category": "meta_data",
                                  "extra_info": null,
                                  "ioc": "Missing META data field: total_edit_time",
                                  "type": "ioc"
                              },
                              {
                                  "category": "meta_data",
                                  "extra_info": null,
                                  "ioc": "Missing META data field: author",
                                  "type": "ioc"
                              },
                              {
                                  "category": "meta_data",
                                  "extra_info": null,
                                  "ioc": "Missing META data field: last_saved_by",
                                  "type": "ioc"
                              },
                              {
                                  "category": "meta_data",
                                  "extra_info": null,
                                  "ioc": "Missing META data field: version",
                                  "type": "ioc"
                              },
                              {
                                  "category": "meta_data",
                                  "extra_info": null,
                                  "ioc": "Missing META data field: num_pages",
                                  "type": "ioc"
                              },
                              {
                                  "category": "meta_data",
                                  "extra_info": null,
                                  "ioc": "Missing META data field: num_words",
                                  "type": "ioc"
                              },
                              {
                                  "category": "meta_data",
                                  "extra_info": null,
                                  "ioc": "Missing META data field: num_chars",
                                  "type": "ioc"
                              }
                          ],
                          "name": "edr_missing_meta_data_content",
                          "severity": 1
                      }
                  ],
                  "analysis_type": "static",
                  "detection": {
                      "permalink": "https://www.virustotal.com/file/7472cfa6308f8f4712a63d9e44bbbfbb0e7cc8f03ec3a787dcb783d578ea3713/analysis/1563801183/",
                      "positives": 12,
                      "sophos": "",
                      "sophos_ml": "",
                      "total": 53
                  },
                  "document_analysis": {
                      "meta_data": {
                          "bytes": 3488
                      }
                  },
                  "reputation": {
                      "first_seen": "2019-07-22T21:44:50",
                      "last_seen": "2019-07-22T21:44:50",
                      "prevalence": "Low",
                      "score": 31,
                      "score_string": "Unknown reputation"
                  },
                  "score": 10,
                  "submission": "2019-07-23T08:13:12Z"
              }
          }
