rule Win_Worm_Hybris_13
{
strings:
	$a0 = { 48594252495300fc684c504000ff1500504000a34224400083c4848bcc50e87c0000005ea135 }

condition:
	$a0
}

        
