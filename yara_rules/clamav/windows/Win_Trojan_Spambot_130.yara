rule Win_Trojan_Spambot_130
{
strings:
	$a0 = { 446f144dfe51f54803d902d57ee7d78cbfffffff56ba95116273fa77c56ed7c45168cb3743806a4e14aa7d99092b7795abd77fffff8810fe0e3ea315e0d74a36ec73e6ee9695f272e8e4135f1fffffffff80f53bfc7f30efbca1a5d3af04a7c453d256fcfc8294eb87d7399fe9ae }

condition:
	$a0
}

        
