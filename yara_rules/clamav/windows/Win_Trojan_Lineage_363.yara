rule Win_Trojan_Lineage_363
{
strings:
	$a0 = { 7b80e958e09d1bff5f08ee01c4f46ae8316fe60cca3f719394d96e844aeee60338fe79b8bac5d7237400097b887b9fa1110bb05d52b0bc0340bb2e8aa69a7b783dce36a9a38e82cab17c2ca62f4892b5de4f382161a561764310929794d0a15fb8faf93bef7ae9cc8eebf3859618180e18c995968df70c34a832466a7b366d71295f0d75d65059 }

condition:
	$a0
}

        