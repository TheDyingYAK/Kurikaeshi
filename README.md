# Kurikaeshi
Service to automatically hash exe files that are placed in the home and root directorys

![alt text](img/repetition.png)


### Compile
1. Install the dependencies
```bash
sudo apt update && sudo apt install inotify-tools -y

```


### Set up the Systemd Service
1. Create the service file:
```bash
sudo cp pe_monitor_files /etc/systemd/system/pe_monitor_files.service
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