rule Win_Trojan_Wangx_1
{
strings:
	$a0 = { 6e65776d73672e736574417474616368656d656e742861747461636873282929 }

condition:
	$a0
}

        
