rule Win_Trojan_Hacdef_55
{
strings:
	$a0 = { d757a901eefc1966cb5653f6b552d22d8b2ffdf20e759b578c3074bfb788d8da1370f6798f6dd7a3e49610b0578753daa1de674e1b1bb87b8afadbff1b9d04875675d90e880b98b20f028a8d4d3bb45e0e5525adc4d3ff110ebb }

condition:
	$a0
}

        
