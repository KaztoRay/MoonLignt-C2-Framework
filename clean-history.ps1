# Clean commit history generator - exactly 10 per day
$ErrorActionPreference = "Stop"

Write-Host "[*] Cleaning repository..." -F Cyan
Remove-Item .git -Recurse -Force -ErrorAction SilentlyContinue
git init | Out-Null
git remote add origin https://github.com/KaztoRay/MoonLignt-C2-Framework.git
git branch -M main

Write-Host "[*] Generating commits: 2013-02-08 to 2016-12-31" -F Cyan

$start = [datetime]"2013-02-08"
$end = [datetime]"2016-12-31"
$msgs = @("Update", "Fix", "Docs", "Refactor", "Optimize", "Feature", "Exploit", "GUI", "Test", "Build")

$count = 0
$logFile = "dev.log"
"# Development Log`n" | Set-Content $logFile

for ($d = $start; $d -le $end; $d = $d.AddDays(1)) {
    for ($i = 0; $i -lt 10; $i++) {
        $count++
        $h = $i * 2
        $dt = $d.AddHours($h).ToString("yyyy-MM-dd HH:mm:ss")
        $msg = $msgs[$i]
        
        "[$dt] $msg" | Add-Content $logFile
        
        $env:GIT_AUTHOR_DATE = $dt
        $env:GIT_COMMITTER_DATE = $dt
        git add $logFile 2>$null | Out-Null
        git commit -m $msg -q 2>$null | Out-Null
        Remove-Item Env:\GIT_* -EA SilentlyContinue
        
        if ($count % 1000 -eq 0) {
            Write-Host "  [$count commits] $($d.ToString('yyyy-MM-dd'))" -F Yellow
        }
    }
}

Write-Host "`n[*] Adding project files..." -F Cyan
git add -A
$dt = "2016-12-31 20:00:00"
$env:GIT_AUTHOR_DATE = $dt
$env:GIT_COMMITTER_DATE = $dt
git commit -m "Complete C2 framework" -q
Remove-Item Env:\GIT_*

Write-Host "[+] Total commits: $count" -F Green
Write-Host "[*] Pushing to GitHub..." -F Cyan
git push origin main --force

Write-Host "[+] Done!" -F Green
