rule Win_Trojan_Mybot_8390
{
strings:
	$a0 = { 177fe698672ac993274d9d1e0e9bb87ab01f0a29eb10e84417a83735d5503ae832d98dde9865fefc7ea358b23d1f1b5bbeaff20ff4b09d3f59bb14afdf47ed5aa314bb0026b7268afad8cc1a33a4a296c170029a5d }

condition:
	$a0
}

        
