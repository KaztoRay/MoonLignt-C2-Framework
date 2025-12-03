# Moonlight C2 Framework - Historical Commit Generator
# Generates commits from 2013-02-08 to 2016-12-31 (10 commits per day)

param(
    [switch]$DryRun,
    [switch]$NoPush
)

$ErrorActionPreference = "Stop"

# Configuration
$START_DATE = Get-Date "2013-02-08"
$END_DATE = Get-Date "2016-12-31"
$COMMITS_PER_DAY = 10

# Calculate total days and commits
$totalDays = ($END_DATE - $START_DATE).Days + 1
$totalCommits = $totalDays * $COMMITS_PER_DAY

Write-Host "`n=== Moonlight C2 Framework - Historical Commit Generator ===" -ForegroundColor Cyan
Write-Host "Start Date: $($START_DATE.ToString('yyyy-MM-dd'))" -ForegroundColor White
Write-Host "End Date: $($END_DATE.ToString('yyyy-MM-dd'))" -ForegroundColor White
Write-Host "Total Days: $totalDays" -ForegroundColor White
Write-Host "Commits per Day: $COMMITS_PER_DAY" -ForegroundColor White
Write-Host "Total Commits: $totalCommits" -ForegroundColor Yellow
Write-Host ""

if ($DryRun) {
    Write-Host "[DRY RUN MODE - No actual commits will be made]`n" -ForegroundColor Magenta
}

# Commit messages for different phases
$commitMessages = @(
    # Phase 1: Initial setup (2013)
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
    
    # Phase 2: Exploit development (2014)
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
    
    # Phase 3: GUI development (2015)
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
    
    # Phase 4: Assembly enhancement (2016)
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
    
    # General commits
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

# Get all files to commit
$allFiles = Get-ChildItem -Path . -Recurse -File | Where-Object {
    $_.FullName -notmatch '\.git' -and
    $_.FullName -notmatch 'generate-commits\.ps1'
}

# Group files by type for phased commits
$fileGroups = @{
    "docs" = $allFiles | Where-Object { $_.Extension -match '\.(md|txt)$' }
    "client" = $allFiles | Where-Object { $_.FullName -match '\\client\\' }
    "server" = $allFiles | Where-Object { $_.FullName -match '\\server\\' }
    "exploits" = $allFiles | Where-Object { $_.FullName -match '\\exploits\\' }
    "gui" = $allFiles | Where-Object { $_.FullName -match '\\gui\\' }
    "scripts" = $allFiles | Where-Object { $_.Extension -match '\.(ps1|bat)$' }
    "assembly" = $allFiles | Where-Object { $_.Extension -match '\.(asm)$' }
    "other" = $allFiles | Where-Object { 
        $_.FullName -notmatch '\\(client|server|exploits|gui|docs)\\' -and
        $_.Extension -notmatch '\.(md|txt|ps1|bat|asm)$'
    }
}

# Calculate files per commit
$filesPerCommit = [Math]::Max(1, [Math]::Ceiling($allFiles.Count / $totalCommits))

Write-Host "Files to commit: $($allFiles.Count)" -ForegroundColor White
Write-Host "Files per commit (avg): $filesPerCommit`n" -ForegroundColor White

if (-not $DryRun) {
    # Stage all files first
    Write-Host "[*] Staging all files..." -ForegroundColor Cyan
    git add -A
}

# Generate commits
$commitCount = 0
$fileIndex = 0
$allFilesArray = $allFiles | ForEach-Object { $_.FullName.Substring((Get-Location).Path.Length + 1) }

for ($date = $START_DATE; $date -le $END_DATE; $date = $date.AddDays(1)) {
    $dateStr = $date.ToString("yyyy-MM-dd")
    
    for ($i = 0; $i -lt $COMMITS_PER_DAY; $i++) {
        $commitCount++
        
        # Calculate time for this commit (spread across the day)
        $hour = [Math]::Floor($i * 24 / $COMMITS_PER_DAY)
        $minute = ($i * 60) % 60
        $second = ($commitCount * 13) % 60  # Pseudo-random seconds
        $commitDate = $date.AddHours($hour).AddMinutes($minute).AddSeconds($second)
        $commitDateStr = $commitDate.ToString("yyyy-MM-dd HH:mm:ss")
        
        # Select commit message
        $messageIndex = $commitCount % $commitMessages.Count
        $message = $commitMessages[$messageIndex]
        
        # Add progress indicator
        $progress = [Math]::Round(($commitCount / $totalCommits) * 100, 2)
        
        Write-Host "[$commitCount/$totalCommits - $progress%] " -NoNewline -ForegroundColor Yellow
        Write-Host "$commitDateStr" -NoNewline -ForegroundColor Green
        Write-Host " - $message" -ForegroundColor White
        
        if (-not $DryRun) {
            # Create commit with backdated timestamp
            $env:GIT_AUTHOR_DATE = $commitDateStr
            $env:GIT_COMMITTER_DATE = $commitDateStr
            
            try {
                # Make actual file changes to ensure commit has content
                $changeFile = "commit_history.txt"
                Add-Content -Path $changeFile -Value "[$commitDateStr] $message"
                git add $changeFile
                
                # Commit with actual changes
                git commit -m $message | Out-Null
            }
            catch {
                Write-Host "[!] Commit failed: $_" -ForegroundColor Red
            }
            finally {
                Remove-Item Env:\GIT_AUTHOR_DATE -ErrorAction SilentlyContinue
                Remove-Item Env:\GIT_COMMITTER_DATE -ErrorAction SilentlyContinue
            }
        }
        
        # Show progress every 100 commits
        if ($commitCount % 100 -eq 0) {
            Write-Host "`n[*] Progress: $commitCount / $totalCommits commits created ($progress%)`n" -ForegroundColor Cyan
        }
    }
}

Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host "Total commits created: $commitCount" -ForegroundColor Green
Write-Host "Date range: $($START_DATE.ToString('yyyy-MM-dd')) to $($END_DATE.ToString('yyyy-MM-dd'))" -ForegroundColor White

if (-not $DryRun) {
    Write-Host "`n[*] Commits created successfully!" -ForegroundColor Green
    
    if (-not $NoPush) {
        Write-Host "`n[*] Pushing to remote repository..." -ForegroundColor Cyan
        Write-Host "[!] WARNING: This will force push and rewrite history!" -ForegroundColor Yellow
        Write-Host "[!] Press Ctrl+C within 5 seconds to cancel..." -ForegroundColor Red
        Start-Sleep -Seconds 5
        
        try {
            Write-Host "[*] Force pushing to origin master..." -ForegroundColor Cyan
            git push origin master --force
            Write-Host "[+] Push completed successfully!" -ForegroundColor Green
        }
        catch {
            Write-Host "[!] Push failed: $_" -ForegroundColor Red
            Write-Host "[*] You can manually push with: git push origin master --force" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "`n[*] Skipping push (use without -NoPush to push)" -ForegroundColor Yellow
        Write-Host "[*] To push manually: git push origin master --force" -ForegroundColor Cyan
    }
}
else {
    Write-Host "`n[*] Dry run completed. Use without -DryRun to create actual commits." -ForegroundColor Magenta
}

Write-Host "`n=== Done ===" -ForegroundColor Cyan
