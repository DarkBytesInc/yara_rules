rule Win_Worm_Mita_1
{
strings:
	$a0 = { 6f6e6b657920262022616e74692d766972757320696e7374616c6c65722e6578652e76627322 }
	$a1 = { 6c65204d79576f726d2c2045646f6e6b657920262022456d65696e656d202d204675 }

condition:
	$a0 and $a1
}

        