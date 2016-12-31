# Batch Commit Generator - Stable Version
param(
    [int]$BatchSize = 10,
    [int]$PushEvery = 50
)

$start = [datetime]"2013-08-03"
$end = [datetime]"2016-12-31"
$totalDays = ($end - $start).Days + 1

Write-Host "`n=== Moonlight C2 - Complete History Generator ===" -F Cyan
Write-Host "[*] Period: $($start.ToString('yyyy-MM-dd')) to $($end.ToString('yyyy-MM-dd'))" -F Yellow
Write-Host "[*] Total days: $totalDays" -F Yellow
Write-Host "[*] Commits to create: $($totalDays * 10)" -F Yellow
Write-Host ""

$msgs = @("Update", "Fix", "Docs", "Refactor", "Optimize", "Feature", "Exploit", "GUI", "Test", "Build")
$current = (git log --oneline 2>$null | Measure-Object -Line).Lines
if (!$current) { $current = 0 }

$count = $current

for ($d = $start; $d -le $end; $d = $d.AddDays(1)) {
    
    for ($i = 0; $i -lt 10; $i++) {
        $count++
        $h = $i * 2
        $timestamp = $d.AddHours($h).ToString("yyyy-MM-dd HH:mm:ss")
        $message = $msgs[$i]
        
        # Create temp file
        $tempFile = "temp_$($d.ToString('yyyyMMdd'))_$i.log"
        "[$timestamp] $message" > $tempFile
        
        # Commit with backdated timestamp
        $env:GIT_AUTHOR_DATE = $timestamp
        $env:GIT_COMMITTER_DATE = $timestamp
        
        git add $tempFile 2>&1 | Out-Null
        git commit -m $message -q 2>&1 | Out-Null
        
        Remove-Item Env:\GIT_* -EA SilentlyContinue
        Remove-Item $tempFile -Force -EA SilentlyContinue
    }
    
    # Progress update and push
    if ($count % $PushEvery -eq 0) {
        Write-Host "  [$count commits] $($d.ToString('yyyy-MM-dd'))" -F Green
        git push origin main --force -q 2>&1 | Out-Null
        Write-Host "  [Pushed to GitHub]" -F Cyan
    }
    
    # Milestone marker
    if ($count % 500 -eq 0) {
        Write-Host "`n  === Milestone: $count commits ===" -F Magenta
        Write-Host ""
    }
}

# Final push
Write-Host "`n[*] Performing final push..." -F Cyan
git push origin main --force

$final = (git log --oneline 2>$null | Measure-Object -Line).Lines
$firstDate = git log --format="%ai" --reverse 2>$null | Select-Object -First 1
$lastDate = git log --format="%ai" -1 2>$null

Write-Host "`n=== COMPLETE ===" -F Green
Write-Host "[+] Total commits: $final" -F Green
Write-Host "[+] Date range: $firstDate" -F Cyan
Write-Host "            to: $lastDate" -F Cyan
