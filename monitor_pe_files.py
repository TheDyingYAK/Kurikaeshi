# python script to monitor for PE files and automatically generate an md5 hash of the file

import os
import hashlib
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from datetime import datetime

# Directory to monitor
WATCH_DIR = os.path.expanduser("~/monitored_directory")
# Log file to store hashes
LOG_FILE = os.path.expanduser("~/pe_file_hashes.log")

class PEFileHandler(FileSystemEventHandler):
    def on_created(self, event):
        # Check if it's a file that ends with '.exe'
        if not event.is_directory and event.src_path.endswith(".exe"):
            file_path = event.src_path
            print(f"New PE file detected {file_path}")
            # Calculate MD% hash
            md5_hash = self.calculate_md5(file_path)
            if md5_hash:
                # Log the hash
                with open(LOG_FILE, "a") as log_file:
                    log_file.write(f"{datetime.now()}: {file_path} - MD5: {md5_hash}\n")
                print(f"MD5 hash recorded: {md5_hash}")

    @staticmethod
    def calculate_md5(file_path):
        try:
            with open(file_path, "rb") as f:
                md5 = hashlib.md5()
                while chunk := f.read(8192):
                    md5.update(chunk)
                return md5.hexdigest()
        except Exception as e:
            print(f"Error calculating MD% for {file_path}: {e}")
            return None

if __name__ == "__main__":
    # Ensure the directory exists
    os.makedirs(WATCH_DIR, exist_ok=True)

    print(f"Monitoring directory: {WATCH_DIR}")
    event_handler = PEFileHandler()
    observer = Observer()
    observer.schedule(event_handler, WATCH_DIR, recursive=False)

    try:
        observer.start()
        print("Press Ctrl+c to stop.")
        while True:
            pass
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

