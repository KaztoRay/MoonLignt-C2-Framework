# Fast Bulk Commit Generator
# 2013-02-08 to 2016-12-31, 10/day

$ErrorActionPreference = "SilentlyContinue"

$S = [datetime]"2013-02-08"
$E = [datetime]"2016-12-31"

$m = @("Add server", "Fix bug", "Update", "Refactor", "Improve", "Optimize", "Add feature", 
       "Fix exploit", "Add GUI", "Update docs")

Write-Host "[*] Starting bulk commit generation..." -F Cyan
Write-Host "[*] Target: $(($E-$S).Days * 10) commits" -F Yellow

# Clean start
if (Test-Path .git) { Remove-Item .git -Recurse -Force }
git init | Out-Null
git remote add origin https://github.com/KaztoRay/MoonLignt-C2-Framework.git
git branch -M master

# Create log file
"# Moonlight C2 Development History`n`n" | Set-Content log.txt

$n = 0
for ($d = $S; $d -le $E; $d = $d.AddDays(1)) {
    for ($i = 0; $i -lt 10; $i++) {
        $n++
        $h = $i * 2  # 0,2,4,6,8,10,12,14,16,18
        $dt = $d.AddHours($h).ToString("yyyy-MM-dd HH:mm:ss")
        $msg = $m[$i]
        
        "[$dt] $msg`n" | Add-Content log.txt
        
        $env:GIT_AUTHOR_DATE = $dt
        $env:GIT_COMMITTER_DATE = $dt
        git add log.txt | Out-Null
        git commit -m $msg | Out-Null
        Remove-Item Env:\GIT_* -EA SilentlyContinue
        
        if ($n % 1000 -eq 0) {
            Write-Host "  [$n commits] $($d.ToString('yyyy-MM-dd'))" -F Green
        }
    }
}

Write-Host "`n[+] Generated $n commits!" -F Green
Write-Host "[*] Pushing to GitHub..." -F Cyan
git push origin master --force
Write-Host "[+] Complete!" -F Green
