rule Win_Trojan_Ghost21_2
{
strings:
	$a0 = { 45646974536572766572000d01130047686f7374207365727665722065 }

condition:
	$a0
}

        
