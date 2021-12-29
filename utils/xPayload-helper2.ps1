<# Run this to generate "36n98..." string #>
$secondPart = [system.io.file]::readalltext("C:\\dh\\xSecondPart.txt")
$charArray = $secondPart.ToCharArray()
$result = ""

foreach ($char in $charArray){
	$result += [string][int]$char + $( @('n','&','b','D','W','X','J','>','I',';') | Get-Random)
}