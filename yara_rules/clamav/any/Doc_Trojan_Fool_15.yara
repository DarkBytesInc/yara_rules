rule Doc_Trojan_Fool_15
{
strings:
	$a0 = { 6e7456657273696f6e5c52756e222c202253757065724e6f76612229203d2022433a5c57696e646f77735c53797374656d5c4261636b75705c57616c7275532e76627322 }
	$a1 = { 2023312c202257656c636f6d655f4d7367426f785f5469746c655f54657874203d2022225375 }

condition:
	$a0 and $a1
}

        