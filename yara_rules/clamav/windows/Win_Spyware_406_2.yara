rule Win_Spyware_406_2
{
strings:
	$a0 = { 7f807fd136b5a3d822592bd31095419c70b8b721bcb821a6f678e52cccaecae778dd0c28002141d28a98e1f10d65fb04873e6cf8757c459d7ca4016c6dfcb52a7afda13a4ee92f626e84e3a696cc }

condition:
	$a0
}

        
