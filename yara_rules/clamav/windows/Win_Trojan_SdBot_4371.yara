rule Win_Trojan_SdBot_4371
{
strings:
	$a0 = { 3cbdb3e4a0bd681a8e26e07aee718d4db4bd9fd6e88ee157b9b0b5df1bdaf6b462348d1041bb3beade18a3bc77688ababa7ab9a24ac8530ad61b5fb4470fc0f8cb5258ad3cbfdf4559b4ab3793be46d1584a895db5b8ac1e020f68da47e346b56a529fb5b5bd681a07acb0d891ea5a86ff561ce5b5bd68479e60eb0334fcf383 }

condition:
	$a0
}

        
