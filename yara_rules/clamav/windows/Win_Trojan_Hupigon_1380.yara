rule Win_Trojan_Hupigon_1380
{
strings:
	$a0 = { cf2861118f9879b09caa61cdd859a4abb653f02e9576a4fcfbb1c69001b318ebc47bb78c77659cda70eaecffada94cac3a89e33f9e768cf85d97cd5abe2f290c59e1fda6963e68c4e68a40de9977f8910f94d5792cb6e8ad2f73fb61f40195e16e151a629b701f67d5dce313287d824ff4d9e056cf81 }

condition:
	$a0
}

        