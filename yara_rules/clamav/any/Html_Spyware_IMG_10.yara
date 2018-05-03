rule Html_Spyware_IMG_10
{
strings:
	$a0 = { 3c696672616d652077696474683d223022206865696768743d223022 }

condition:
	$a0
}

        
