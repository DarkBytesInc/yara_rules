rule Win_Trojan_Agent_33790
{
strings:
	$a0 = { f904ef7a09602b41ed3c365f8fc9d26ac9f064ade96ba03188d84416e7c5887e3151f3cf795fe79ef443f06daeb52dd50a77ad26c51bc37d920bb45afef1a27b4c7f425b13e03f05a2fa074ec4e0baf1b8b1271d9ccda52bd6f0 }

condition:
	$a0
}

        
