rule Win_Spyware_Banker_2514
{
strings:
	$a0 = { 51fa2985200cd4ada2ebbac49c23ebe3cf9938f7dc9c6a2a58167666c4bfa449f52db3f5f3c9112628b1c5cbcf2bebf94abbad26019d64b5670e925542522887ba9863e2aae22ba12aaaf843ee9b9786a9e6979e20d3ad5c8afff692eb3767bfa2472e856e500e716590a070fd40550515191c75c2412b04dbcaf5ae924339ab9e1a5f0186d4643741a31707 }

condition:
	$a0
}

        