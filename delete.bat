@echo off
echo Running the script and checking for dump.pcap...

:: Run your Python script here, if necessary
:: python your_script.py

:: Check if dump.pcap exists and delete it
if exist dump.pcap (
    echo Found dump.pcap, deleting...
    del dump.pcap
    echo File deleted.
) else (
    echo No dump.pcap file found.
)
