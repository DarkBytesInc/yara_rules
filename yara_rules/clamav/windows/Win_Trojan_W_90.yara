rule Win_Trojan_W_90
{
strings:
	$a0 = { 48594252495300fc684c604000ff1500604000a34224400083c4848bcc50e87c000000 }

condition:
	$a0
}

        
