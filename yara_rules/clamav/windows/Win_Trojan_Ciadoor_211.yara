rule Win_Trojan_Ciadoor_211
{
strings:
	$a0 = { 9c9ced8594879c9c28e689ed0b9d059cacbc9d853c879c9c287505b9d8dd9d05c9d8dd9d850f879c9ced850d879c9c2ae64d05d9d8dd9d05e9d8dd9d85f7879c9ced85f5879c9c2ae65105f1d8dd9d05c9d8dd9d85df879c9ced85dd879c9c2ae65d05fd }

condition:
	$a0
}

        
