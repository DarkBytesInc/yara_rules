rule Win_Trojan_Mybot_8008
{
strings:
	$a0 = { ac526e28e7659729e2d141d9a2611354919fa9c5ce1ef07b4c59d2ce24cd5cb533489456a5f36151fd02f00f001cc83cad68aceb1ef8b3c239f42e933f3bbe808039c463133522577f5fdcd5c8c1e41d95a9547c13a3db69b6504df1240cb914399a5a8df660013cd6fd455a1a0339ebf4314f9e0641b14e1cc4610acbf3710bc0bbe050ad349889aeb5 }

condition:
	$a0
}

        