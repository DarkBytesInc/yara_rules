rule Win_Trojan_SdBot_1124
{
strings:
	$a0 = { bff14d9287308279f8a71b90d01668f538d351b024d818adc57a57c4b49c99a3eb11d2683bcbd9be3b9d93ee4bc259f938324b8caf2f7790749ce872d62d5a14cf395bddff636dba8c988ca244b2dee76c0d87f165be9f68947075e2c9d8d75cc15e8c2ad1dfec5e4a9545636cac71540a5a0dc6665c5ee2e24ec06c82f290ef4368af3f83f34afe5cf591736648cc7d13b85499728f }

condition:
	$a0
}

        