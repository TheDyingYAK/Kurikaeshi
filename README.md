# Kurikaeshi
Service to automatically hash any exe file created in the users directory

![alt text](img/repetition.png)


### Install Prerequisites
1. Ensure Python3 is installed:
```bash
sudo apt update
sudo apt install python3 python3-pip -y
```

2. Install the requirements
```bash
python3 -m pip install -r requirements.txt
```

3. Ensure the python script "monitor_pe_files.py" is executable
```bash
chmod +x monitor_pe_files.py
```

### Set up the Systemd Service
1. Create the service file:
```bash
sudo vim /etc/systemd/system/pe_monitor.service
```

2. Add the following content to the file:
```bash
[Unit]
Description=Monitor directory for new PE files and generate MD5 hashes
After=network.target

[Service]
ExecStart=/usr/bin/python3 /home/your_username/pe_monitor/monitor_pe_files.py
Restart=always
User=your_username
WorkingDirectory=/home/your_username/pe_monitor

[Install]
WantedBy=multi-user.target
```

### Enable and Start the Service
1. Reload systemd to recognize the new service
```bash
sudo systemctl daemon-reload
```

2. Enable the service to start on boot
```bash
sudo systemctl enable pe_monitor.service
```

3. Start the service
```bash
sudo systemctl start pe_monitor.service
```

4. Verify the service status
```bash
sudo systemctl status pe_monitor.service
```

### Test the Service
1. Create the monitored directory is it doesn't already exist:
```bash
mkdir ~/monitored_directory
```

2. Place a .exe file in the directory
```bash
cp som_file.exe ~/monitored_directory/
```

3. Check the log file for the MD5 hash:
```bash
cat ~/pe_file_hashes.log
```


### Debugging
If you encounter any issues, check the logs:
```bash
sudo journalctl -u pe_monitor.service
```
This setup ensures that the service runs automatically, monitors the specified directory for new .exe files, and logs their MD5 hashes