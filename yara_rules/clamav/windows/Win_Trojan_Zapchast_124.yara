rule Win_Trojan_Zapchast_124
{
strings:
	$a0 = { 6e313d2a2e2a3a2f6463632073656e64[0-20]73656e642024312024322d[0-128]6e333d6861636b6572 }

condition:
	$a0
}

        
