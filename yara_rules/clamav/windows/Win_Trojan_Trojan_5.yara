rule Win_Trojan_Trojan_5
{
strings:
	$a0 = { f8fe2a14eb0a0bb7b91fbb8b098b08898d14e7174805b34d8a6fcc182d40470958d8ffcc486550738d559452b810aa6cbfff7e8bc48b8d2d89088b954407500410485cd848f748114c0c2e5072c8218354585cfe9fcf6d9714ff8b9552ff5138dbe2898510e680ffed0b83bd05007d23 }

condition:
	$a0
}

        