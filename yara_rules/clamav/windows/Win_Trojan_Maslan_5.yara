rule Win_Trojan_Maslan_5
{
strings:
	$a0 = { 9ae894dc79f69d7dfdd6ab5b6a1ec4dcaf53bda8a8be4b6726d58827900455d3962b9dbc1eaf6b3a29f017410d3970f626b2bbc97fdb285e7afd6b97ab65a6a1baefdebc012ebbbbf3bda4993f652a68b5e6f7ee3b5671fdeee413d3 }

condition:
	$a0
}

        
