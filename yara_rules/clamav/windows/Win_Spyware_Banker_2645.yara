rule Win_Spyware_Banker_2645
{
strings:
	$a0 = { e378d01dae52529cbdad9f00121d6aa707a9aaf3f0e2956310bc1142957be9d83a7c59410f5b9d33587d79d9a8830c0b2c175dcd80fa50a8bc7f3e501e7b439c13ee8be19f55fcbc7a4e202361ef0dc5789ffe883d6595b34ad40f893aaed3a02f55 }

condition:
	$a0
}

        
