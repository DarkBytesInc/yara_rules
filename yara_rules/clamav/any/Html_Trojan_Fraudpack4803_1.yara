rule Html_Trojan_Fraudpack4803_1
{
strings:
	$a0 = { 4b00006a0000564d4f716400556157006f000058485a0046436f4258575139660000000076686e7842004200643945000057530000000000635100003934000049006c00350000446c6f005535550000004f00004e00004e6400006c370058005600790046380000750000540057530000677600006f7937745550664b }

condition:
	$a0
}

        