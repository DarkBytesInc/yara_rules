rule Win_Trojan_Bancos_1415
{
strings:
	$a0 = { 894b1eae2e72f6876f7eccad7098a8dbc65f09075a3a99aea8a003aea4059dfdd13417eb42450dfaddd3803d21baac8e2f03ffa48681305a198cc4ae42a1d2969aca7786e292dae08adc0144420baf7948dab3f5e80fe3f889dcfd41 }

condition:
	$a0
}

        
