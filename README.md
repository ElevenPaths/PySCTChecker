CertificateTransparency-SCTChecker 
====================================

Description
-----------
This is a Quick and dirty Python script for checking if a domain implements properly Certificate Transparency. If so, it is possible to observe how Certificate Transparency is implemented on the server side.
When a server implements Certificate Transparency, it must offer at least one SCT (a proof of inclusion of the server TLS Certificate into a Transparency Log). A SCT can be offered by three different ways: embedded in the certificate, as a TLS extension and via OCSP Stapling. Using CertificateTransparency-SCTChecker is possible to identify the delivery options that the server uses and the logs in which the certificate has been sent. Also, it is possible to check if the offered SCTs are valid and legitimately signed by logs.

Functionality
-------------
  -	 **Usage**: 
  
          python CertificateTransparency-SCTChecker/ct_domains_sct_checker.py [domain1 domain2 ...]

  -	 **Output example:**

      user@ubuntu:~/Desktop/CertificateTransparency-SCTChecker$ python ct_domains_sct_checker.py elevenpaths.com

      ** Connecting to host: elevenpaths.com... **

      ** Looking for embedded SCT in certificate **

      ** Looking for SCTs in TLS extensions**
        > No sct found on TLS

      ** Looking for SCTs in OCSP response **
        > OCSP address not found
        > No sct found in OCSP response

      ** Logs detected in SCTs **
        > Symantec log (precert)
          └─ Verified signature: True

        > Google 'Pilot' log (precert)
          └─ Verified signature: True

        > Google 'Rocketeer' log (precert)
          └─ Verified signature: True


  -	 **Dependencies:**

      - To run CertificateTransparency-SCTChecker is necessary to have **OpenSSL** installed on the OS
      - To install python modules dependencies, run:

            sudo pip install -r CertificateTransparency-SCTChecker/requirements.txt

Related tools
-------------

- https://www.elevenpaths.com/labstools/certificate-transparency-checker-firefox/index.html
- https://github.com/Torvel/ct-tools/blob/master/submit-cert.py