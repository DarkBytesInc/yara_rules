rule Win_Trojan_Agent_36988
{
strings:
	$a0 = { 5368656c6c45786563757465 }
	$a1 = { 463a5c7367686772666175736b666c6a6b6a72675c73676668617368686a73665c7361666273676a6661732e706462 }

condition:
	$a0 and $a1
}

        