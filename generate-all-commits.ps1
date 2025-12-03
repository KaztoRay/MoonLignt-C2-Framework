# Moonlight C2 - Complete History Generator
# Creates commits from 2013-02-08 to 2016-12-31 (10 per day)

$ErrorActionPreference = "Stop"

# Configuration
$START_DATE = Get-Date "2013-02-08"
$END_DATE = Get-Date "2016-12-31"
$COMMITS_PER_DAY = 10

Write-Host "`n=== Moonlight C2 Historical Commit Generator ===" -ForegroundColor Cyan
Write-Host "Creating commits from $($START_DATE.ToString('yyyy-MM-dd')) to $($END_DATE.ToString('yyyy-MM-dd'))" -ForegroundColor White
Write-Host "Commits per day: $COMMITS_PER_DAY`n" -ForegroundColor White

# Commit messages
$messages = @(
    "Initial project structure",
    "Add basic C2 server framework",
    "Implement TCP listener",
    "Add client implant skeleton",
    "Implement basic command handler",
    "Add encryption support",
    "Improve error handling",
    "Add logging functionality",
    "Refactor network code",
    "Update documentation",
    "Add MS08-067 exploit",
    "Add MS17-010 exploit",
    "Add MS03-026 exploit",
    "Improve exploit reliability",
    "Add exploit launcher",
    "Fix exploit bugs",
    "Optimize exploit performance",
    "Add exploit documentation",
    "Update exploit database",
    "Refactor exploit code",
    "Start GUI development",
    "Add session management UI",
    "Add listener configuration UI",
    "Add exploit browser UI",
    "Improve GUI layout",
    "Add menu system",
    "Add status bar",
    "Improve UI responsiveness",
    "Add GUI icons",
    "Polish GUI appearance",
    "Add assembly modules",
    "Implement direct syscalls",
    "Add anti-analysis features",
    "Implement RC4 in assembly",
    "Add stealth capabilities",
    "Improve EDR bypass",
    "Add process injection",
    "Optimize assembly code",
    "Add monitoring features",
    "Add control features",
    "Code cleanup",
    "Fix compilation warnings",
    "Update README",
    "Add comments",
    "Improve code quality",
    "Fix memory leaks",
    "Optimize performance",
    "Add error checking",
    "Update build system",
    "Fix bugs"
)

# Initialize history file
$historyFile = "DEVELOPMENT_HISTORY.md"
Set-Content -Path $historyFile -Value "# Moonlight C2 Framework - Development History`n`n"

# Add initial files
git add -A
git commit -m "Initial commit - Project setup" | Out-Null

Write-Host "[*] Starting commit generation..." -ForegroundColor Cyan
$commitCount = 0
$totalDays = ($END_DATE - $START_DATE).Days + 1
$totalCommits = $totalDays * $COMMITS_PER_DAY

for ($date = $START_DATE; $date -le $END_DATE; $date = $date.AddDays(1)) {
    for ($i = 0; $i -lt $COMMITS_PER_DAY; $i++) {
        $commitCount++
        
        # Calculate commit time (spread throughout the day)
        $hour = [Math]::Floor($i * 24 / $COMMITS_PER_DAY)
        $minute = ($i * 60) % 60
        $second = ($commitCount * 17) % 60
        $commitDateTime = $date.AddHours($hour).AddMinutes($minute).AddSeconds($second)
        $commitDateStr = $commitDateTime.ToString("yyyy-MM-dd HH:mm:ss")
        
        # Select message
        $message = $messages[$commitCount % $messages.Count]
        
        # Add unique content to history file
        Add-Content -Path $historyFile -Value "## Commit #$commitCount - $commitDateStr"
        Add-Content -Path $historyFile -Value "**Action:** $message"
        Add-Content -Path $historyFile -Value "**Status:** Completed`n"
        
        # Stage changes
        git add $historyFile
        
        # Set commit date
        $env:GIT_AUTHOR_DATE = $commitDateStr
        $env:GIT_COMMITTER_DATE = $commitDateStr
        
        # Create commit
        try {
            git commit -m $message | Out-Null
            
            # Progress indicator
            if ($commitCount % 100 -eq 0) {
                $progress = [Math]::Round(($commitCount / $totalCommits) * 100, 2)
                Write-Host "[$commitCount/$totalCommits - $progress%] $commitDateStr" -ForegroundColor Green
            }
        }
        catch {
            Write-Host "[!] Failed at commit $commitCount" -ForegroundColor Red
        }
        finally {
            Remove-Item Env:\GIT_AUTHOR_DATE -ErrorAction SilentlyContinue
            Remove-Item Env:\GIT_COMMITTER_DATE -ErrorAction SilentlyContinue
        }
    }
}

Write-Host "`n[+] Total commits created: $commitCount" -ForegroundColor Green
Write-Host "[*] Pushing to GitHub..." -ForegroundColor Cyan
Write-Host "[!] This will force push! Press Ctrl+C within 3 seconds to cancel..." -ForegroundColor Yellow
Start-Sleep -Seconds 3

try {
    git push origin master --force
    Write-Host "[+] Successfully pushed to GitHub!" -ForegroundColor Green
}
catch {
    Write-Host "[!] Push failed: $_" -ForegroundColor Red
    Write-Host "[*] Manual push: git push origin master --force" -ForegroundColor Yellow
}

Write-Host "`n=== Complete ===" -ForegroundColor Cyan
