rule Win_Trojan_SdBot_2333
{
strings:
	$a0 = { c46d0bcb5b56072f1f57af37cd39b0c31d3e294f0301227e8537de09aa3e2864b40aa797d69ec2a1b212fba094e07cc3154172ca080669c27ddd47da8daa9bb7747fb18ac2485fa23e89dcfaea220aae51be95f969 }

condition:
	$a0
}

        
