rule Win_Trojan_Agent_36005
{
strings:
	$a0 = { 68ff8fea7fe8b0000000e8b7000000c1e806e8000000005903c1ffd06a00e89d000000c39090909058eb05e884000000b8aeaeaeaebfed1a4000b9040000008b1733d05283c704e2f65468e01a4000e87800000050e878000000ba0010400052b9e00a00 }

condition:
	$a0
}

        