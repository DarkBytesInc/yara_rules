rule Win_Trojan_Bancos_1874
{
strings:
	$a0 = { 3a9d9e750e0a239e94545d6f3f759573884a7f45957b6cee1e6eeaeb4e0398efd74e44444caf0c35889c0e42efe7ef6cbfae4320f676dc558c5e365f29920135626a22c7624b }

condition:
	$a0
}

        
