rule Win_Trojan_Worker_2
{
strings:
	$a0 = { ba042a41008bc3e8effaffff8d85e0fdffff8d95f8feffffb900010000e8cd13ffff8d85e0fdffffba3c2a4100e8f113ffff8b85e0fdffffe8ce15ffff8bd08d85e4fdffffe8b901ffff8d95e4fdffff8d85e4feffffe88813ffff8b8de4feffff8d45fcba542a4100e8f913ffff8d8ddcfdffffba602a41008bc3e843fcffff }

condition:
	$a0
}

        
