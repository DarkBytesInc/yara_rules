rule Win_Trojan_Mybot_5972
{
strings:
	$a0 = { 3bcc10971eef721da7c4f5cc6acf947622add3cb5c8f71a62d8b82e6429060f21aad1e15eb3d17dff3421d1b831bb7bd075451e82fd98c463940c48199ab30f9d3b35ebbeb55a34fcd06f8bd4ddd4464a45b4fd8afeae697a13eb97168dd3118cd73d617 }

condition:
	$a0
}

        
