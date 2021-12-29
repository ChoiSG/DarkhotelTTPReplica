# Source: https://github.com/PowerShellMafia/PowerSploit/blob/master/ScriptModification/Out-CompressedDll.ps1

# DLL 파일 읽은 뒤 "압축" (Compress)
$FileBytes = [system.io.file]::readallbytes("C:\\dh\\darkhotel-downloader.dll")
$Length = $FileBytes.Length
$CompressedStream = New-Object IO.MemoryStream
$DeflateStream = New-Object IO.Compression.DeflateStream ($CompressedStream, [IO.Compression.CompressionMode]::Compress)
$DeflateStream.Write($FileBytes, 0, $FileBytes.Length)
$DeflateStream.Dispose()
$CompressedFileBytes = $CompressedStream.ToArray()
$CompressedStream.Dispose()

# 압축된 스트림을 base64 인코딩 
$d = [Convert]::ToBase64String($CompressedFileBytes)

# 다크호텔식 난독화 
$c = $d -replace [RegEx]::Escape('+'), '-'
$b = $c -creplace 'A','#'
$a = $b -replace '6','@'