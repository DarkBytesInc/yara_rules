rule Html_Trojan_InjectorCdrive_1
{
strings:
	$a0 = { 265277[0-200]46756c6c53637265656e[2]436f6e736f6c65[1]73616d706c65 }

condition:
	$a0
}

        
