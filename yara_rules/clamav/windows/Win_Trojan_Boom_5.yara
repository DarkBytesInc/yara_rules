rule Win_Trojan_Boom_5
{
strings:
	$a0 = { 3643008b03e8b0f3feffb970664300ba881f43008b03e89ff3feffb97c664300ba283443008b03e88ef3feff8b03e817f4feff5be865f7fcff8be55dc300ffffffff0e000000494351204d61696c626f6d62 }

condition:
	$a0
}

        
