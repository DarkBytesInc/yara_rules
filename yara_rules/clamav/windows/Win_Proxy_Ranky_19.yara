rule Win_Proxy_Ranky_19
{
strings:
	$a0 = { 35d450d72a66c4ed657856fd17f552242ea8b5a4c4382275e584b7482d40f726967a60b37a70434f28213721b818650a75676668c670f6f7525c6c41f3694b3945600a38738d690548646b3821351370253d84bf16ca22156684a6639d41f7f52cc034a760e65f56f3747e2fd0b2077ff349e31c60315739f89c9d70f6b364a36d4821af5c33422cc838cc8e70b368291a2bfc }

condition:
	$a0
}

        