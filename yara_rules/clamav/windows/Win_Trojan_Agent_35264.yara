rule Win_Trojan_Agent_35264
{
strings:
	$a0 = { f064ade96ba03188d84416e7c5887e3151f3cf795fe79ef443f06daeb52dd50a77ad26c51bc37d920bb45afef1a27b4c7f425b13e03f05a2fa074ec4e0baf1b8b1271d9ccda52bd6f04b574700ee255df0310189e7069f777cdf }

condition:
	$a0
}

        
