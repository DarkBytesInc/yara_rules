rule Win_Spyware_Banker_4572
{
strings:
	$a0 = { 10e41e3140d3e96c48717fc4661a293fcfd3b7fefde198dac56ec764e7166a84f472f39f27cca3046dc3517809a8e9e160ad25a2f9f183696f2d578e7e7afa1cf02cbb2f8f10f0bdfc91a75023bcfb32835900e6406ceccfead1966bfbaa6c80a1fa4697 }

condition:
	$a0
}

        
