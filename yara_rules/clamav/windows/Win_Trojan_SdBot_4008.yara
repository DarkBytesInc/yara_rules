rule Win_Trojan_SdBot_4008
{
strings:
	$a0 = { 47f39e0548f28881aa2370d6cc417d955609effef376039467dff17011916cbc7b58c8abed644c72827382b818a12f44080bb823611d2490c710017215c66c15aae33c752a935053f183965b88a9a7eb17ccd0875397bc80b3cc }

condition:
	$a0
}

        