rule Win_Trojan_Hackarmy_9
{
strings:
	$a0 = { a38c5025891d9005addd3db6f740ae0f85bc058945f81db0ddedb7ef45fca31a8d0d8943fc8b73317b08950ff62fdbdd84a8228d0c76898f747d56558d6b102edfdbeeedec8bbc00a3302f8b550b02a3340942fb7e6fee04a338077051b91434 }

condition:
	$a0
}

        
