rule Win_Tool_Crypter_38
{
strings:
	$a0 = { 53746f6e65277320205065457865456e63727970746572 }

condition:
	$a0
}

        
