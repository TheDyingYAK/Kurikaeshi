# Kurikaeshi
Service to automatically hash exe files that are placed in the home and root directorys

![alt text](img/repetition.png)


### Compile
1. Install the dependencies
```bash
sudo apt update
sudo apt install g++ libssl-dev
```

2. Compile the program
```bash
g++ -std=c++20 -o monitor_pe_files monitor_pe_files.cpp -lssl -lcrypto
```


### Set up the Systemd Service
1. Create the service file:
```bash
sudo vim /etc/systemd/system/pe_monitor_files.service
```

2. Add the following content to the file:
```bash
[Unit]
Description=Monitor directory for new PE files and generate MD5 hashes
After=network.target

[Service]
ExecStart=/usr/bin/python3 /home/your_username/pe_monitor/monitor_pe_files
Restart=always
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
You can manually test the program by simply running the executable and putting a .exe in one of the monitored directories
```bash
sudo ./monitor_pe_files
```
This setup ensures that the service runs automatically, monitors the specified directory for new .exe files, and logs their MD5 hashes


### Performance considerations
intify limits: Increase the inotify watch limit to handle many directories
```bash
echo "fs.inotify.max_user_watches=524288" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```



