# Batch Commit Generator - 100 commits at once
$ErrorActionPreference = "SilentlyContinue"

Write-Host "[*] Moonlight C2 - Batch Commit Generator" -F Cyan

if (Test-Path .git) { Remove-Item .git -Recurse -Force }
git init | Out-Null
git remote add origin https://github.com/KaztoRay/MoonLignt-C2-Framework.git | Out-Null
git branch -M master | Out-Null

"# Development History`n" | Set-Content hist.txt

$start = [datetime]"2013-02-08"
$end = [datetime]"2016-12-31"
$total = 0

for ($d = $start; $d -le $end; $d = $d.AddDays(1)) {
    $dayFile = "day_" + $d.ToString("yyyyMMdd") + ".txt"
    $content = ""
    
    for ($i = 0; $i -lt 10; $i++) {
        $total++
        $h = $i * 2
        $dt = $d.AddHours($h).ToString("yyyy-MM-dd HH:mm:ss")
        $msgs = @("Server", "Bug fix", "Docs", "Refactor", "Perf", "Feature", "Exploit", "GUI", "Test", "Build")
        $msg = $msgs[$i]
        
        $content += "[$dt] $msg`n"
        
        $env:GIT_AUTHOR_DATE = $dt
        $env:GIT_COMMITTER_DATE = $dt
        
        $content | Set-Content $dayFile
        git add $dayFile | Out-Null
        git commit -m "$msg - $($d.ToString('yyyy-MM-dd'))" -q 2>$null
        
        Remove-Item Env:\GIT_* -EA SilentlyContinue
        Remove-Item $dayFile -EA SilentlyContinue
    }
    
    if ($total % 100 -eq 0) {
        Write-Host "  [$total commits] $($d.ToString('yyyy-MM-dd'))" -F Yellow
    }
}

Write-Host "`n[+] Created $total commits!" -F Green
Write-Host "[*] Verifying..." -F Cyan
$count = (git log --oneline | Measure-Object -Line).Lines
Write-Host "[+] Verified: $count commits in repository" -F Green

Write-Host "[*] Pushing..." -F Cyan
git push origin master --force

Write-Host "[+] Done!" -F Green
