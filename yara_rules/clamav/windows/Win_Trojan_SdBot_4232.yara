rule Win_Trojan_SdBot_4232
{
strings:
	$a0 = { 2967ccf59c724eddfc3f76ca5110fb5255992e89538e0ba6842f4cd8faecb8d6ef0dc5b63e3baef518094ddb7a6fae12de8c9db3a9f4b3894699a2e444ba5d45c706860e4b28820e878a8e4c0d3aaca1c852154387ce12b35415fa4bbb7d5655ecf40024907619917070244108f73ec044083a00635658e3a9a50e9a4bfc04ef038c89b8 }

condition:
	$a0
}

        