rule Win_Trojan_Injector_21
{
strings:
	$a0 = { 83c364575381c6be3100006a0156ff15????4000 }
	$a1 = { 558bec837d08645356578bf175??e9????0000 }
	$a2 = { ffd0b80054010033ffe9????0000 }
	$a3 = { 0fb68c30????00008d59043bd375??0fb69430????00008d59033bd375??0fb69430????00008d59013bd375??0fb69430????000083c1023bd174 }

condition:
	$a0 and $a1 and $a2 and $a3
}

        
