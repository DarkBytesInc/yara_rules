rule Win_Trojan_GK_1
{
strings:
	$a0 = { 903a79906b7956f8466967780d7456bc463467c0b551d3908b774bb8f6a056d8e16744870c70427e }

condition:
	$a0
}

        
