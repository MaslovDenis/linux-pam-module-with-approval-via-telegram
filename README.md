![reliability](https://github.com/MaslovDenis/linux-pam-module-with-approval-via-telegram/raw/main/media/reliability.svg) 
![maintainability](https://github.com/MaslovDenis/linux-pam-module-with-approval-via-telegram/raw/main/media/maintainability.svg)
![security](https://github.com/MaslovDenis/linux-pam-module-with-approval-via-telegram/raw/main/media/security.svg)
![vulnerabilities](https://github.com/MaslovDenis/linux-pam-module-with-approval-via-telegram/raw/main/media/vulnerabilities.svg)

![quality gate](https://github.com/MaslovDenis/linux-pam-module-with-approval-via-telegram/raw/main/media/quality_gate.svg)
# Linux pam module with approval via telegram 

Authorization module using ssh keys and confirmation of entry in the telegram.

![demo](https://github.com/MaslovDenis/linux-pam-module-with-approval-via-telegram/raw/main/media/demo.gif)


## !!! WARNING: 

Before starting the installation, make sure that your ssh keys are added to the server ! ! !

---
### Install server:
- Copy tcp_server.py to the server that will control the ssh login. This should be a server that users will not connect to. 

#### Usage

- Run tcp_server.py [parameters]
   
    Parameters:
    
        --bind-address, -ip
            help='Server ip', 
            default='127.0.0.1'
        --bind-port, -p 
            help='Server port', 
            default='8686'
        --api-token, -t 
            help='Telegram API token', 
            required=True
        --approver, -a 
            help='Telegram user id for approve', 
            required=True

---
### Install client:

If the telegram tcp server is not available, then the entry will be made using the MFA.
To use the MFA, you must enter the OTP secret.

Run the command
python3 otp_encrypt.py -s "Your OTP secret"

And paste the result of execution into the approve_auth.py file in the "otp_secret" variable (line 9) 

- install python2.7
        
        apt update &&
        apt install python2.7
  
- install python PAM
  
        dpkg -i libpam-python_1.0.8-1_amd64.deb

- install python OTP
  
        wget http://ftp.br.debian.org/debian/pool/main/p/python-pyotp/python-pyotp_2.2.7-1_all.deb
        dpkg -i python-pyotp_2.2.7-1_all.deb

- copy ./approve_auth.py to the /usr/lib/security/auth.py
  
        cp ./approve_auth.py /usr/lib/security/auth.py

- make backup files 

        cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
        cp /etc/pam.d/sshd /etc/pam.d/sshd.backup

- copy pam module and sshd config

        cp ./etc/ssh/sshd_config /etc/ssh/sshd_config
        cp ./etc/pam.d/sshd /etc/pam.d/sshd

- the following parameters must be specified in the /etc/pam.d/sshd in JSON format : 
        
        auth      required    pam_python.so /usr/lib/security/auth.py {"group":"{GROUP}","server-ip":"{TCP_SERVER_IP}","server-port":{TCP_SERVER_PORT}}
        {GROUP} - the group whose members should receive login confirmation
        {TCP_SERVER_IP}
        {TCP_SERVER_PORT}

-     service sshd restart
---

