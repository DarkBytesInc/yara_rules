rule Win_Trojan_Packed_15
{
strings:
	$a0 = { 5bb8af1204502d7210045003c38130d2aec978e8e3000000e9c00000005f68[0-200]5e59c3e83bffffff6881c9ab86686587c15a33c06578 }

condition:
	$a0
}

        
