rule Doc_Trojan_Ded_3
{
strings:
	$a0 = { 3e203020416e64204e6f742064203d2022202220416e64204e6f742064203d2022205f2220416e64204e6f742064203d20222220416e64204e6f74204d696428642c20312c203129203d20222722205468656e }
	$a1 = { 5768696c65204d696428642c204c656e286429202d20312c20322920 }
	$a2 = { 756c652e496e736572744c696e65732069202a20322c2064 }

condition:
	$a0 and $a1 and $a2
}

        