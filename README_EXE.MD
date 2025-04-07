# Windows Executable for Secure Receiving

The Windows Executable is more secure for the socket script because it allows the port to be tied to a specific executable program, ensuring that only that designated EXE communicates on port `12346`.

We will create the receiver executable to allow secure receiving on Windows.

## Requirements

1. **PyInstaller**  
   Install PyInstaller using pip:
   ```bash
   pip install pyinstaller

2) Creating the Executable
- From a terminal in the main folder, run:
   ```bash
   python -m PyInstaller --onefile --windowed secure_receiver.py

3) Cleanup Build Files:
- From a terminal in the main folder, run the `Exe_Cleanup.py` script to fix the folders and delete unnecessary files.

4) Verify the Rule:
- In Windows Powershell, run:
```powershell
Get-NetFirewallRule -DisplayName "Allow Secure Receiver Port 12346" | Get-NetFirewallApplicationFilter

A path to you executable should be shown... ie: C:\...\...\...\secure_receiver.exe
