rule Doc_Trojan_Fool_4
{
strings:
	$a0 = { 526567697374657265644f776e65722229203d20225468652057614c527553 }
	$a1 = { 696e666563742e5642436f6d706f6e656e74732e496d706f7274202822633a5c526964646c65722e7379732229 }

condition:
	$a0 and $a1
}

        