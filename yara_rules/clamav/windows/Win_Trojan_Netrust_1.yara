rule Win_Trojan_Netrust_1
{
strings:
	$a0 = { 5aa5226aa7d5f20f797a661fdaa735fa2a702a6552a6a18620eaa7562aa78d3a3c1d1aa91c3aa5946a3f267aa99abaa99cdaa99efaa9351110003b036801f000bc0d9804ff03410000000406004c6162656c310001011700436f707972696768742031393938204576314c43304445 }

condition:
	$a0
}

        