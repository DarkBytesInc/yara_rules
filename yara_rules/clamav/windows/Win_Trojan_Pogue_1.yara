rule Win_Trojan_Pogue_1
{
strings:
	$a0 = { b103d3cd8bcdbd6e8581cd0f748bf5bd923b03ee33e981ed0cb18b9e230d81c3649d879e230dbb318f2bddbd338f2beb75e88bddb103d3cb84639cc05b639db91f519fb8f3e36228a88d935f4108fbc0543d7630bde2980810cb5463cc2fbd }

condition:
	$a0
}

        
