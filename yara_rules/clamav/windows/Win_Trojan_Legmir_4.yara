rule Win_Trojan_Legmir_4
{
strings:
	$a0 = { 59596683bdff7efbfc5502740abee90405d2ff75080cb883cfff6fedc1fe8945dc3bc7750a11caeb0d7d3cdc6a0467effe6358b28bd885db0f84027f6a066a0198acbb2d3fcb3bc78884e9046802316404eddf97ef5c8aa675096a190aa0eb0466 }

condition:
	$a0
}

        
