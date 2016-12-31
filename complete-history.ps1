# Fast Commit Generator - Remaining Period
$ErrorActionPreference = "SilentlyContinue"

$start = [datetime]"2013-08-03"
$end = [datetime]"2016-12-31"

Write-Host "[*] Generating commits from $($start.ToString('yyyy-MM-dd')) to $($end.ToString('yyyy-MM-dd'))" -F Cyan

$msgs = @("Update server", "Fix bug", "Update docs", "Refactor", "Optimize", "Add feature", "Fix exploit", "Update GUI", "Add test", "Update build")

$n = (git log --oneline | Measure-Object -Line).Lines
$pushInterval = 100

for ($d = $start; $d -le $end; $d = $d.AddDays(1)) {
    for ($i = 0; $i -lt 10; $i++) {
        $n++
        $h = $i * 2
        $dt = $d.AddHours($h).ToString("yyyy-MM-dd HH:mm:ss")
        $msg = $msgs[$i]
        
        # Create unique file for each commit
        $file = "dev_log_$($d.ToString('yyyyMMdd'))_$i.txt"
        "[$dt] $msg" | Set-Content $file
        
        $env:GIT_AUTHOR_DATE = $dt
        $env:GIT_COMMITTER_DATE = $dt
        git add $file 2>$null | Out-Null
        git commit -m $msg 2>$null | Out-Null
        Remove-Item Env:\GIT_* -EA SilentlyContinue
        Remove-Item $file -EA SilentlyContinue
    }
    
    if ($n % $pushInterval -eq 0) {
        Write-Host "  [$n commits] $($d.ToString('yyyy-MM-dd')) - Pushing..." -F Yellow
        git push origin main --force 2>$null | Out-Null
    }
    
    if ($n % 1000 -eq 0) {
        Write-Host "  [Checkpoint: $n commits completed]" -F Green
    }
}

Write-Host "`n[+] Final push..." -F Cyan
git push origin main --force

$final = (git log --oneline | Measure-Object -Line).Lines
Write-Host "[+] Complete! Total commits: $final" -F Green
Write-Host "[*] Date range: $(git log --format='%ai' --reverse | Select-Object -First 1) to $(git log --format='%ai' -1)" -F Cyan
