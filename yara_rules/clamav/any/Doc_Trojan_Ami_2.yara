rule Doc_Trojan_Ami_2
{
strings:
	$a0 = { 4163746976655f2e5642436f6d706f6e656e74732828416374697665436f6d705f202b203129292e4e616d65203d204d6f64756c4e616d65 }
	$a1 = { 4163746976655f2e5642436f6d706f6e656e7473284d6f64756c4e616d655f292e436f64654d6f64756c652e41646446726f6d537472696e67205669727573436f6465 }

condition:
	$a0 and $a1
}

        