rule Win_Trojan_Istsvc_1
{
strings:
	$a0 = { 2e000c6461366cb2d70b300b76c40f8537be6c2c235055b95f4d41d0e9f160db4300943f273d25699f7b60abdc7e703a2f2f77002e78996f17baaf505c29cd2ff92fde7269f1ec848570002f055fb42e7099eeabbdd00077623bf831037c5c6bed815764267a3078bb66b3f6e6870f4936 }

condition:
	$a0
}

        