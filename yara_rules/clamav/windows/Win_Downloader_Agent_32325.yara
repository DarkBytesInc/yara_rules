rule Win_Downloader_Agent_32325
{
strings:
	$a0 = { dcfd58b234277473c95a042750b5f4faf33d136c2688cb363344cb227e16d03b93e2f2b1b0302168328019f18c113848c6ea6986e0953724e965ce5eb20c74ede68457125caa5cf26df49c2b3c6a0781ffe528de375f8804633a3ec0cdb6fcb512ed88ef198db1fc10e854cdedbd410463ede87682eb0e03e0768bb89ae697a30febddc15a98b1eb67a41985ca6012d8b6b35d4d }

condition:
	$a0
}

        