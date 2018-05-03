rule Win_Ircbot_Septic_5
{
strings:
	$a0 = { 5d81ed5c11b4098d966e11cd21b8004ccd217ec54461724b2e4d655373694168c57e206120 }

condition:
	$a0
}

        
