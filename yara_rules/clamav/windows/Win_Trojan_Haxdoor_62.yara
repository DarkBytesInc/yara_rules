rule Win_Trojan_Haxdoor_62
{
strings:
	$a0 = { 924e1136dd2b487932214f563c4c44520c009a0950a1009d0979f24154cae5589027cf2950415ce74ed8840c9b602b53649964082664e0705fed3321c32674f1db78c820cfa508417ccc3c13f21e458024d184d68558c484883d58c4c8e6158c46f6909b90e785836794c7983ad02c6264337c9c }

condition:
	$a0
}

        