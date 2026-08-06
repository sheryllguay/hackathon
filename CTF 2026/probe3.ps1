$port = 5040
try {
    $tcp = New-Object System.Net.Sockets.TcpClient
    $tcp.BeginConnect("10.181.33.90", $port, $null, $null) | Out-Null
    $ok = $tcp.ConnectAsync().Wait(2000)
    if ($ok) {
        $stream = $tcp.GetStream()
        $stream.WriteTimeout = 2000
        $stream.ReadTimeout = 2000
        # Try sending nothing and read
        try {
            $bytes = New-Object byte[] 256
            $stream.Read($bytes, 0, 256) | Out-Null
            $text = [System.Text.Encoding]::ASCII.GetString($bytes).TrimEnd([char]0)
            Write-Host "5040 empty: $text"
        } catch { Write-Host "5040 empty: timeout/err" }
        $tcp.Close()
    } else { Write-Host "5040: no connect" }
} catch { Write-Host "5040: $_" }

$port = 49689
try {
    $tcp = New-Object System.Net.Sockets.TcpClient
    $tcp.BeginConnect("10.181.33.90", $port, $null, $null) | Out-Null
    $ok = $tcp.ConnectAsync().Wait(2000)
    if ($ok) {
        $stream = $tcp.GetStream()
        $stream.WriteTimeout = 2000
        $stream.ReadTimeout = 2000
        try {
            $bytes = New-Object byte[] 256
            $stream.Read($bytes, 0, 256) | Out-Null
            $text = [System.Text.Encoding]::ASCII.GetString($bytes).TrimEnd([char]0)
            Write-Host "49689 empty: $text"
        } catch { Write-Host "49689 empty: timeout/err" }
        $tcp.Close()
    } else { Write-Host "49689: no connect" }
} catch { Write-Host "49689: $_" }
