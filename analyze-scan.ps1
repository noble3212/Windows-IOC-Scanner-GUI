$csv = Import-Csv 'C:\Users\user3\Downloads\malware-scan-2026-07-28_15-46-45.csv'
Write-Host "`n=== FINDINGS BY CATEGORY ===" -ForegroundColor Cyan
$csv | Group-Object Category | Sort-Object Count -Descending | Format-Table Count, Name -AutoSize
Write-Host "`n=== FINDINGS BY SEVERITY ===" -ForegroundColor Cyan
$csv | Group-Object Severity | Sort-Object Count -Descending | Format-Table Count, Name -AutoSize
Write-Host "`n=== CRITICAL FINDINGS ===" -ForegroundColor Red
$csv | Where-Object Severity -eq 'CRITICAL' | Format-Table Category, Description, Path -AutoSize
Write-Host "`n=== HIGH FINDINGS (first 20) ===" -ForegroundColor DarkRed
$csv | Where-Object Severity -eq 'HIGH' | Select-Object -First 20 | Format-Table Category, Description, Path -AutoSize
