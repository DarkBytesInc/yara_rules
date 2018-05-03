rule Win_Worm_Petik_12
{
strings:
	$a0 = { 2f6f056561647469746c653e4f6e6c7920466f7220596f7521bf9fb5d93c2f140722626f6479367363b9 }

condition:
	$a0
}

        
