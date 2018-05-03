rule Win_Worm_Mimail_8
{
strings:
	$a0 = { 9090909089c890909090f7f790909090 }
	$a1 = { 9090????90??9090 }
	$a2 = { 909190909090905890 }
	$a3 = { 9031309090909001f890909090e2??90909090 }
	$a4 = { 67e9ed60ffff }

condition:
	$a0 and $a1 and $a2 and $a3 and $a4
}

        
