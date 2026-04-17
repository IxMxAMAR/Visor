Set-Location "$PSScriptRoot\tests"
Start-Process "C:\Program Files\Bochs-3.0\bochs.exe" "-q -unlock -f bochs\windows_intel.bxrc"
Start-Sleep 8

Write-Output "=== Bochs serial output ==="
try {
    $client = New-Object System.Net.Sockets.TcpClient("127.0.0.1", 14449)
    $stream = $client.GetStream()
    $stream.ReadTimeout = 2000   # 2s block before giving up
    $reader = New-Object System.IO.StreamReader($stream)
    $end    = [DateTime]::UtcNow.AddSeconds(50)
    $idle   = 0
    while ([DateTime]::UtcNow -lt $end -and $idle -lt 8) {
        try {
            $line = $reader.ReadLine()
            if ($null -ne $line) {
                Write-Output $line
                $idle = 0
            } else {
                $idle++
            }
        } catch [System.IO.IOException] {
            $idle++   # read timeout — keep trying until $idle limit
        }
    }
    $client.Close()
} catch {
    Write-Output ("Serial error: " + $_.Exception.Message)
}
Write-Output "=== done ==="
