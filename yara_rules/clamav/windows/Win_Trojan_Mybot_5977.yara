rule Win_Trojan_Mybot_5977
{
strings:
	$a0 = { bc29a95ce5df1c1df27df20e86834172aec553fe0082256d922e59dcec3df3148c0a47c70f5147baf2a5bd4d55f0f438f2a9b3ce808f840ba5bfd65ded24ff1a028d9fe75ba1f158c923aadfcae7d272a9922945c7 }

condition:
	$a0
}

        
