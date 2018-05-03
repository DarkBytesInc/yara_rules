rule Win_Worm_Stuxnet_14
{
strings:
	$a0 = { 74006d00700072006f00780079002e00 }
	$a1 = { 520045005c005300[0-16]69006e00430043005c005300650074 }

condition:
	$a0 and $a1
}

        
