rule Win_Trojan_Hupigon_323
{
strings:
	$a0 = { 76a0abe7ba51d44dfe077ad7dd2a4cf464970190626ed870c16eabf0f9d662bc90c3e3ee2611b9ed8f9fe291cff99e84dc2b08a84dca67cee357edd0ca252aeb5cf447f3661b7436248e33a35a18e174eb51d367629105e97a8c }

condition:
	$a0
}

        
