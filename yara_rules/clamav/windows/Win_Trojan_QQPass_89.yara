rule Win_Trojan_QQPass_89
{
strings:
	$a0 = { 5f9efcf8833fcfb9cab2be8a82d50bd66b80bceabb183636b169f5c322bb458f8349117fcefe6a0d82004e5786466e2015c424d2ce71f6e2b0c393f60dffc88d31a6b1a2a39da28dc09c4e78330eefa9af9fdeab399fb16afda5a1aee3870066f1cd91e08e50d36e4260f38c7e234a8e9765a9dc983fad7d7ad338d4d8 }

condition:
	$a0
}

        
