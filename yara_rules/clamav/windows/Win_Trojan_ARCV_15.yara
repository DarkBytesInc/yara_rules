rule Win_Trojan_ARCV_15
{
strings:
	$a0 = { 33f6e89802e89502b42acd2180fe01751080fa07730bb409ba0d0303d6cd21ebfe8b848b038b9c8d03a30001891e0201b805ffcd213dfb007403e81200bb0001 }

condition:
	$a0
}

        
