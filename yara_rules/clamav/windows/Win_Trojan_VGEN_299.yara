rule Win_Trojan_VGEN_299
{
strings:
	$a0 = { 0660e800005dbe040033c08ec02689360400262b2e040083ed02508cd0fc8ed044bf80004c1f03fe8b0589048b4502 }

condition:
	$a0
}

        
