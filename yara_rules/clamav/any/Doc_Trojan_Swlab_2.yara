rule Doc_Trojan_Swlab_2
{
strings:
	$a0 = { 576f726442617369632e4d6163726f436f7079204d61634e616d65242c2022476c6f62616c3a536b616d6d79222c2031 }
	$a1 = { 576f726442617369632e43616c6c20226173646173646164616422 }

condition:
	$a0 and $a1
}

        