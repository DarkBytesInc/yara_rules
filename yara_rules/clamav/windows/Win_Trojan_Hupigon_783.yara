rule Win_Trojan_Hupigon_783
{
strings:
	$a0 = { b179c9bdf0da51ccf8ed896f0f3cbd98b5241ada14b147eda0a7213658925a685ecd26d39ca85c7f4ae81d3cb8f44459ad98a8777c12f990b9839b5b453f381c045c89cc6f5b7309ca7dbb63aafc739ccf04a5dba9cd59be5c4e }

condition:
	$a0
}

        
