rule Win_Trojan_Mybot_97
{
strings:
	$a0 = { 6255b279e5cd17f1af99f17072767c5f4a6f576f6f4435c5005701473ca25a48dd9b38fe21662d4c69667f5629760b707d10a4356147756eda09f45e }

condition:
	$a0
}

        