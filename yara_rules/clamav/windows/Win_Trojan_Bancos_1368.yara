rule Win_Trojan_Bancos_1368
{
strings:
	$a0 = { 26ea84d0d4d6d7e1eb7f1dee0f7ddee6931a3a532e508efec37d0eb0dc0da1d61c34fe4cb86e7f1ae06cc0710ddadef24404ee09d51b38bbc188f266dc26c2f3805d8bf79f92c57ca6707d3df5409be2439248a17276589d79a4ffd712118fbb409a74c49c71b474 }

condition:
	$a0
}

        
