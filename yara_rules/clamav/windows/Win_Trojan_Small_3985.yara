rule Win_Trojan_Small_3985
{
strings:
	$a0 = { 0fc1d0e83300000009c0742e31d20fc1c281c2fe??40008d8a58f000ff8d894414ff005231c005ffdf0db02902c10a02c1021183c20439ca75 }

condition:
	$a0
}

        
