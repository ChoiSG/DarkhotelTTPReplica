$psSource = [system.io.file]::readalltext("C:\\dh\\s.ps1")
$psSource = $psSource.ToCharArray()

foreach ($element in $psSource) 
{ 
	$hexPayload = $hexPayload + " " + [System.String]::Format("{0:X2}", [System.Convert]::ToUInt32($element))
}