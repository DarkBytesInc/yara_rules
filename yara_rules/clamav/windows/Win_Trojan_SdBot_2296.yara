rule Win_Trojan_SdBot_2296
{
strings:
	$a0 = { 7ae867a56d2e62b1ce85da1942d54c90bc67af2f38c88c6972fd174f74dc946f3e16647109b23bdf7c9316d1efc88758e5241dbb4dad08da22ec9da70103a6d3fac9dc97e4848fcac48d0bf6faaf4f1270aa2d285bac00647133bac46301bad4bb53d6 }

condition:
	$a0
}

        
