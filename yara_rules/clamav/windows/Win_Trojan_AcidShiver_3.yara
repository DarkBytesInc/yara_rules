rule Win_Trojan_AcidShiver_3
{
strings:
	$a0 = { 48656c70006d6f645368656c6c0000000066726d4368617400434841545f44656673000000434841545f46756e6374696f6e7300005443505f44656673000000005443505f46756e6374696f6e730000004368616f733233320000000057696e736f636b320000000068766c726174 }

condition:
	$a0
}

        