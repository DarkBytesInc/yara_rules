rule Win_Trojan_FraudPack_23
{
strings:
	$a0 = { 5589e5ba00f0060081ea00f0060081c290fdffff535756515283c9ff4181c1f0440e0089cf8365a4008d55a431db52526a0053ff158422650083e8570f85180300008365a4008d4da431d251526a00ff15882265008365a4008d5da431d2536a0052ff15802265008365a4008d4da431db51536a00ff15802265008365a4008d }

condition:
	$a0
}

        