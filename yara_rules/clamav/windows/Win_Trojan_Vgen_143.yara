rule Win_Trojan_Vgen_143
{
strings:
	$a0 = { 4010ba5e000500003b060200721bb409ba1801cd21cd204e6f7420656e6f756768206d656d6f7279242d20008ed02d }

condition:
	$a0
}

        
