rule Win_Trojan__0536_0002_002_1
{
strings:
	$a0 = { 15000026c745170000b440b90300ba7a06cd218a0eb10626884d04e8ce00e9b100807c184074f7 }

condition:
	$a0
}

        
