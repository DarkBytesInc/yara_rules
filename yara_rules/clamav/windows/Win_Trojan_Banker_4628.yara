rule Win_Trojan_Banker_4628
{
strings:
	$a0 = { 76697065727468656d616e[0-5]4156502e54726179[0-16]436f6e736f6c65[0-1]46756c6c53637265656e }

condition:
	$a0
}

        
