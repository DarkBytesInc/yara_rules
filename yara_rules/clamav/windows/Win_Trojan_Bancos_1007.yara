rule Win_Trojan_Bancos_1007
{
strings:
	$a0 = { 4a4af69b1c98c85573d7ceb2ca03d788a4a8585ab9d6e750b692bf921459bd870c8cc3c3d85f0b4253e5b05a9ff7e915f0197bbf83b48047bd4ac3d8da3e202bd802f524d4c3e0bbb74554891aeeaa604fdffb2c72 }

condition:
	$a0
}

        
