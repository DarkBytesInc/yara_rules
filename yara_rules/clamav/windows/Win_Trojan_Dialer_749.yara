rule Win_Trojan_Dialer_749
{
strings:
	$a0 = { 41004c00450052002ea1348032687474703a2f2f7777772e656e65726779706c756769 }

condition:
	$a0
}

        
