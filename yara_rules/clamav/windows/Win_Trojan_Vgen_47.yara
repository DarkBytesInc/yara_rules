rule Win_Trojan_Vgen_47
{
strings:
	$a0 = { 6563686f206f66660d0a3a3a1b5b386d202d2d2d205b5a6f505f425d20426174636820496e666563746f72202d2d2d }

condition:
	$a0
}

        
