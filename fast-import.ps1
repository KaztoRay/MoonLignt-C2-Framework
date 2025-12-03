# Git Fast-Import Bulk Commit Generator
# Ultra-fast method for 14,000+ commits

$START = [datetime]"2013-02-08"
$END = [datetime]"2016-12-31"

Write-Host "[*] Generating fast-import stream..." -F Cyan

$stream = @()
$stream += "reset refs/heads/master"

$commitNum = 1
$mark = 1

for ($date = $START; $date -le $END; $date = $date.AddDays(1)) {
    for ($i = 0; $i -lt 10; $i++) {
        $hour = $i * 2
        $timestamp = $date.AddHours($hour)
        $ts = [int]([DateTimeOffset]$timestamp).ToUnixTimeSeconds()
        
        $msgs = @("Add server code", "Fix bug", "Update docs", "Refactor code", 
                  "Improve performance", "Add feature", "Fix exploit", "Update GUI",
                  "Add test", "Update build")
        $msg = $msgs[$i]
        
        $content = "[$timestamp] Commit $commitNum - $msg`n"
        
        $stream += ""
        $stream += "commit refs/heads/master"
        $stream += "mark :$mark"
        $stream += "author Developer <dev@moonlight.c2> $ts +0000"
        $stream += "committer Developer <dev@moonlight.c2> $ts +0000"
        $stream += "data " + $msg.Length
        $stream += $msg
        if ($commitNum -eq 1) {
            $stream += "M 644 inline history.log"
        } else {
            $stream += "from :" + ($mark - 1)
            $stream += "M 644 inline history.log"
        }
        $stream += "data " + $content.Length
        $stream += $content
        
        $mark++
        $commitNum++
        
        if ($commitNum % 1000 -eq 0) {
            Write-Host "  Generated $commitNum commits..." -F Yellow
        }
    }
}

Write-Host "[+] Stream generated! ($commitNum commits)" -F Green
Write-Host "[*] Writing to file..." -F Cyan
[System.IO.File]::WriteAllLines("$PWD\import.dat", $stream, [System.Text.Encoding]::UTF8)

Write-Host "[*] Initializing repository..." -F Cyan
if (Test-Path .git) { Remove-Item .git -Recurse -Force }
git init | Out-Null
git remote add origin https://github.com/KaztoRay/MoonLignt-C2-Framework.git | Out-Null

Write-Host "[*] Importing commits..." -F Cyan
Get-Content import.dat | git fast-import

Write-Host "[*] Pushing to GitHub..." -F Cyan
git branch -M master
git push origin master --force

Write-Host "`n[+] Complete! $($commitNum - 1) commits created" -F Green
Remove-Item import.dat -ErrorAction SilentlyContinue
