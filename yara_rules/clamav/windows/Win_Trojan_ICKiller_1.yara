rule Win_Trojan_ICKiller_1
{
strings:
	$a0 = { 4b07bad111812c746c01c106270000000000000100000000000000000069634b696c6c6572000000000000000049434b696c6c65722049435120436c69656e74730000000000000000ffcc310003870d884b07bad111812c746c01c10627880d884b07bad111812c746c01c106 }

condition:
	$a0
}

        