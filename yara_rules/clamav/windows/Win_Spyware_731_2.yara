rule Win_Spyware_731_2
{
strings:
	$a0 = { a60375cec875cc25e8201d48a62924af09ec22cfcb92c4741c4a687708d8f682f85982c71f1ca45d33e621857ded731970ba9e912859331395952f228ee801a5e892a158216f9a541b259a98e4024b9e27e1d28328dde22a157025390375e22c542700cc6040e7fccf7d12ce89772319ff472aae7e9465b127b6042fa5f32f6c6b3ad228ad71216e522a9d217d1e6cb31d }

condition:
	$a0
}

        