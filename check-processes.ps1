$csv = Import-Csv 'C:\Users\user3\Downloads\malware-scan-2026-07-28_15-46-45.csv'
Write-Host "`n=== MEMORY_RESIDENT processes ===" -ForegroundColor Yellow
$csv | Where-Object Category -eq 'MEMORY_RESIDENT' | ForEach-Object { "$($_.Path) - $($_.Detail)" } | Sort-Object
Write-Host "`n=== THREAD_HIJACK processes (unique) ===" -ForegroundColor Yellow
$csv | Where-Object Category -eq 'THREAD_HIJACK' | ForEach-Object { Split-Path $_.Path -Leaf } | Sort-Object -Unique
Write-Host "`n=== UNUSUAL_PORT processes (unique) ===" -ForegroundColor Yellow
$csv | Where-Object Category -eq 'UNUSUAL_PORT' | ForEach-Object { Split-Path $_.Path -Leaf } | Sort-Object -Unique
Write-Host "`n=== DLL_INJECT ===" -ForegroundColor Yellow
$csv | Where-Object Category -eq 'DLL_INJECT' | Format-Table Description, Path -AutoSize
Write-Host "`n=== HIDDEN_WINDOW ===" -ForegroundColor Yellow
$csv | Where-Object Category -eq 'HIDDEN_WINDOW' | ForEach-Object { Split-Path $_.Path -Leaf } | Sort-Object -Unique
