rule Win_Trojan_Rape_20
{
strings:
	$a0 = { 6a048d75bc8975b88b45b8506a036a008b352ca604088975b88b45b850e8cef8ffff83c4148945b8837db8007d1a68a2900408e868f8ffff83c4046a01e81ef9ffff }
	$a1 = { 3a0a003a3a2072617065 }

condition:
	$a0 and $a1
}

        
