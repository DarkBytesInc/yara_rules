rule Win_Trojan_Bancos_992
{
strings:
	$a0 = { a7561ab02304da0dc6d3d271d53ed5a027e30d0c7d7adc02e86751f062560355f9fec1126486efa59e5c8b9b786a85d5e570f59b228edfb4a8f9c3ed1bfd2dbd47739756ac3c6573d1337717152944deded2f0dd37d325c2 }

condition:
	$a0
}

        
