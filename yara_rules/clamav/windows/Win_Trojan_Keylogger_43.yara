rule Win_Trojan_Keylogger_43
{
strings:
	$a0 = { 59f7f98d45f4508d85ccfeffff508d85ccfeffff68481040005080c2418855f7ff154010400083c4108d85ccfeffff5368800000006a025353680000004050ffd7 }

condition:
	$a0
}

        
