rule Win_Trojan_Klone_28
{
strings:
	$a0 = { 0f279ea74d2065c987c4ecfda4be0ce5ec7bfbb225bc09fb554116df7f239e99a6e290a7992e663fb356ef5184099dbaed6cecc4c2c207d2f8ff7003b88c0f0ef1893931819927c45159c3ee946c12040ccc5d986047b71413bc35dbf23b9eabb9d16672f10f0473811b649b9d16d15bfa1137cc41ebac2efe29be3e35b9d4795f9af20a6c488167a7e9a892 }

condition:
	$a0
}

        