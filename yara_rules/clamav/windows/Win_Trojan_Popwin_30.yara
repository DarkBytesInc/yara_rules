rule Win_Trojan_Popwin_30
{
strings:
	$a0 = { 6827ab26ba44cc67f4bbb5f1cf47597504af442b847afcc5d222b664a7dc8475e12ca351250295e5699c30ff39f0abff9dc607d83342552596194348913c959e45835b1a84d1e8721f95f2b7b242e2cc0523576a5f20c15a7ccf5ba8dcc611ab3595a8b789b94a76de6aaecea43d780a }

condition:
	$a0
}

        