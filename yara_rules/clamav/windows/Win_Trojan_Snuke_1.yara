rule Win_Trojan_Snuke_1
{
strings:
	$a0 = { 4000731d8bc183e11f83e0e7c1f8038b90706d40008d04caf640040174038b00c3c7055461400009000000c7055861400000000000b8ffffffffc3cccccccccccccccccccccccccc6a02e8a9d3ffff83c404c3cccccccccc558bec57568b750c8b7d088b4d103bfe760c8bc603c1 }

condition:
	$a0
}

        
