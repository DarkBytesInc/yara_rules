rule Win_Worm_Autorun_386
{
strings:
	$a0 = { 505083c404890c24c1ce05c1c6052bce8bcc8b0983c404525733fa5f5553575f565733 }

condition:
	$a0
}

        
