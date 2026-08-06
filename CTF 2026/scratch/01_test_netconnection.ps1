$ports = @(135, 139, 445, 902, 912, 5040, 49689)
foreach ($p in $ports) {
    Write-Host "===== TCP/$p ====="
    try {
        $r = Test-NetConnection -ComputerName 10.181.33.90 -Port $p -InformationLevel Detailed -WarningAction SilentlyContinue
        $r | Format-List ComputerName, RemoteAddress, RemotePort, TcpTestSucceeded, NameResolutionResults, InterfaceAlias, SourceAddress, NetRoute
    } catch {
        Write-Host "ERR: $_"
    }
    Write-Host ""
}
