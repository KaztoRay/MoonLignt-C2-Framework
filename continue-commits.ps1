# Continue from 2013-08-02 to 2016-12-31
$ErrorActionPreference = "SilentlyContinue"

Write-Host "[*] Continuing commit generation from 2013-08-02..." -F Cyan

$start = [datetime]"2013-08-02"
$end = [datetime]"2016-12-31"
$total = (git log --oneline | Measure-Object -Line).Lines

$msgs = @("Server", "Bug fix", "Docs", "Refactor", "Perf", "Feature", "Exploit", "GUI", "Test", "Build")

for ($d = $start; $d -le $end; $d = $d.AddDays(1)) {
    $dayFile = "commit_" + $d.ToString("yyyyMMdd") + ".tmp"
    
    for ($i = 0; $i -lt 10; $i++) {
        $total++
        $h = $i * 2
        $dt = $d.AddHours($h).ToString("yyyy-MM-dd HH:mm:ss")
        $msg = $msgs[$i] + " - " + $d.ToString('yyyy-MM-dd')
        
        "[$dt] $msg" | Set-Content $dayFile
        
        $env:GIT_AUTHOR_DATE = $dt
        $env:GIT_COMMITTER_DATE = $dt
        git add $dayFile 2>$null | Out-Null
        git commit -m $msg -q 2>$null | Out-Null
        Remove-Item Env:\GIT_* -EA SilentlyContinue
        Remove-Item $dayFile -EA SilentlyContinue
    }
    
    if ($total % 500 -eq 0) {
        Write-Host "  [$total commits] $($d.ToString('yyyy-MM-dd'))" -F Yellow
        git push origin master --force -q 2>$null
        Write-Host "  [Pushed to GitHub]" -F Green
    }
}

Write-Host "`n[+] Final push..." -F Cyan
git push origin master --force
Write-Host "[+] Complete! Total: $total commits" -F Green
