rule Vbs_Worm_CoolNote_2
{
strings:
	$a0 = { 5072696e7a20436861726c65732041726520446965 }
	$a1 = { 434f4f4c5f4e4f54455041445f44454d4f2e545854??766273 }

condition:
	$a0 and $a1
}

        
