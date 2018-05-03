rule Html_Trojan_ClickerAgent_31
{
strings:
	$a0 = { 558bec81ec3c0200005657e8f077ffffb98e000000bef41800108dbdc8fdfffff3a56830770210ff1598100010 }

condition:
	$a0
}

        
