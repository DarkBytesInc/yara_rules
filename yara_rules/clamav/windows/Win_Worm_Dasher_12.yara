rule Win_Worm_Dasher_12
{
strings:
	$a0 = { 74797065206e756c3e526573756c742e7478740d0d0a53716c5363616e2e6578652053594e }

condition:
	$a0
}

        
