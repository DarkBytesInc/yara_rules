rule Win_Trojan_Tepfer_30
{
strings:
	$a0 = { 8d3d1c21400083c7928b37c1e6108d46906a56598b044803f083eee333c9330e84c974235f51b01c2ac87210582cc0770b68003040005fe914ffffffb85b204000ff50016a7c59e2fef7f100eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee }

condition:
	$a0
}

        
