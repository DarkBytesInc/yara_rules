rule Win_Trojan_Tepfer_21
{
strings:
	$a0 = { 8d35c02f4000bffc3f400083c7045768183140005f83ef6e8b3fc1e7108d773badc1c80803f883c71d33c9030f84c976195f5180e91c7c0a581c767705e95afeffffb815304000ff50ff6a7c59e2fef7f10000d35f7e003effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff }

condition:
	$a0
}

        
