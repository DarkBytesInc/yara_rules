rule Win_Trojan_Mybot_5040
{
strings:
	$a0 = { c5d557d9d82f3f4afa16d3bb77c7cecd37d0b3c110c8c74b851d41da2918e400bd4940f2b6b7b6069dc7ffb2b10908970eb9abaa342cdc16a4a3a2dd6414b7ee5ca09c9a99251c928c9392e9e1783ee08d8c0e4e95739b45898583820e057b757c7bd2cacc778c8225b573fd25a5e36d6c6ba65dde6d259e7aa663b8eee55f575c5bb2aa41d0a95655f53f669350b9cd4c01bf494847 }

condition:
	$a0
}

        