rule Win_Spyware_Banker_3502
{
strings:
	$a0 = { 3778ba757967c3dd9749422003b1f64a471a261f42d74db936d8d9b3fd98508a288cfbff4488e6950c3093c82ff502f27bfa7d1182fdf0f0bd219fc1106d67fa464b6c767338b1ec6a32f9acbfe7d041 }

condition:
	$a0
}

        
