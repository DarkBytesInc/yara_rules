rule Win_Trojan_SdBot_4014
{
strings:
	$a0 = { 16d6f7bf6735ae1b4cc5f77e82df5cfcacc04d7279feca4df0732b62e51d514e5c0a4fdc9f56f22a04c4d3dfa9ddf610e6aac05fb981dde3b681560863812a5bff1ce3a73e88e8aeaeea6d1513719fdcbc8562c8e3387846ba67 }

condition:
	$a0
}

        
