rule Win_Trojan_Tepfer_22
{
strings:
	$a0 = { bffc3f400083c7045768183140005f83ef6e8b3fc1e7108d773badc1c80803f883c71d33c9030f84c9761a5f51b01c2ac87e0a581c767705e91fffffffb851304000ff50ff6a7c59e2fecd0300009db61100390000000a00fefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefe }

condition:
	$a0
}

        
