rule Win_Worm_Blebla_1
{
strings:
	$a0 = { 206d7920726f6d656f203f00ffffffff0200000068690000ffffffff0d0000006c6173742077697368203f3f3f000000ffffffff060000006c6f6c203a29 }

condition:
	$a0
}

        
