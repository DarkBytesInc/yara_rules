rule Win_Trojan_Coced_3
{
strings:
	$a0 = { 585858585858000000007262000059657300cee3f7ece1eaa2d5e3f0ecebece5000055696072716774635a4b6f7467646f6a6f755a4f45575a47616368725a477676755a4f45575a00004d6c536271626e667766717050776271777673466d62616f665362776b000000796c3d25 }

condition:
	$a0
}

        