# Moonlight C2 - Robust Commit Generator
# 2013-02-08 to 2016-12-31, 10 commits/day

$START = Get-Date "2013-02-08"
$END = Get-Date "2016-12-31"
$PER_DAY = 10

$msgs = @(
    "Initial project structure", "Add C2 server", "TCP listener", "Client implant",
    "Command handler", "Encryption", "Error handling", "Logging", "Network refactor",
    "Documentation", "MS08-067 exploit", "MS17-010 exploit", "MS03-026 exploit",
    "Exploit reliability", "Exploit launcher", "Bug fixes", "Performance", 
    "Exploit docs", "Database update", "Code refactor", "GUI development",
    "Session management UI", "Listener config UI", "Exploit browser", "GUI layout",
    "Menu system", "Status bar", "UI responsive", "GUI icons", "GUI polish",
    "Assembly modules", "Direct syscalls", "Anti-analysis", "RC4 assembly",
    "Stealth", "EDR bypass", "Process injection", "Assembly optimize",
    "Monitoring", "Control", "Cleanup", "Fix warnings", "Update README",
    "Comments", "Code quality", "Fix leaks", "Optimize", "Error checking",
    "Build system", "Bug fixes"
)

Write-Host "`n[*] Moonlight C2 - Complete History Generator`n" -ForegroundColor Cyan

# Setup
$hist = "HISTORY.log"
"# Development Log`n" | Out-File $hist -Encoding UTF8
git add -A 2>$null
git commit -m "Project initialization" 2>$null
$total = (($END - $START).Days + 1) * $PER_DAY
$n = 0

for ($d = $START; $d -le $END; $d = $d.AddDays(1)) {
    for ($i = 0; $i -lt $PER_DAY; $i++) {
        $n++
        $h = [Math]::Floor($i * 24 / $PER_DAY)
        $m = ($i * 60) % 60
        $s = ($n * 13) % 60
        $dt = $d.AddHours($h).AddMinutes($m).AddSeconds($s).ToString("yyyy-MM-dd HH:mm:ss")
        $msg = $msgs[$n % $msgs.Count]
        
        # Add content
        "[$dt] $msg" | Add-Content $hist -Encoding UTF8
        git add $hist 2>$null
        
        # Commit
        $env:GIT_AUTHOR_DATE = $dt
        $env:GIT_COMMITTER_DATE = $dt
        git commit -m $msg 2>$null
        Remove-Item Env:\GIT_* -ErrorAction SilentlyContinue
        
        if ($n % 500 -eq 0) {
            $pct = [Math]::Round($n/$total*100,1)
            Write-Host "  [$n/$total - $pct%] $($d.ToString('yyyy-MM-dd'))" -ForegroundColor Yellow
        }
    }
}

Write-Host "`n[+] Created $n commits" -ForegroundColor Green
Write-Host "[*] Pushing... (force)" -ForegroundColor Cyan
git push origin master --force
Write-Host "[+] Done!" -ForegroundColor Green
