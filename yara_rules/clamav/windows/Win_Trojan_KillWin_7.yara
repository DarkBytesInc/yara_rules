rule Win_Trojan_KillWin_7
{
strings:
	$a0 = { 64656c202f66202f73202f7120633a5c2a2e646c6c206563686f20797c666f726d617420643a202f71 }

condition:
	$a0
}

        
