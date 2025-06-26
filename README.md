# financial-services-apim-mediation-policies

This repository contains the mediation policies and the other utility synapse artifacts required for APIM runtime enforcements specific to financial services specific use-cases like Open Banking/ Open Finance. In high level ,it contains;

* APIM Policy .j2 files 
* Java based class mediators
* Synapse handlers
* Custom sequences

There are mediation artifacts common for financial services use-cases and some are specific to regional specification compliane requirements set for Open Banking.


### Building from the source

If you want to build the Financial Services APIM Mediation Policies from the source code:

1. Install Java8 or above.
2. Install [Apache Maven 3.0.5](https://maven.apache.org/download.cgi) or above.
3. Get the Financial Services APIM Mediation Policies from [this repository](https://github.com/wso2/financial-services-apim-mediation-policies.git) by **cloning** or **downloading** the repository as a zip.
    * To **clone the solution**, copy the URL and execute the following command in a command prompt.
      `git clone <the copiedURL>`. After cloning, checkout to the **main** branch.
    * To **download the repository**, select the **main** branch first, then click **Download ZIP** and unzip the downloaded file.
4. Navigate to the cloned/downloaded repository using a command prompt and run the relevant Maven command:

| Command                             | Description                                                                                                                                                                                                |
|:------------------------------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| ```mvn install```                   | This starts building the repository without cleaning the folders.                                                                                                                                          |
| ```mvn clean install```             | This cleans the folders and starts building the repository from scratch.  

5. Once the maven build is successful, navigate to the 'fs-apim-mediation-artifacts/target' folder to get the zip file containing all the
mediation policies,custom sequences, class mediators & handlers to copy in to /lib folder. 
   

