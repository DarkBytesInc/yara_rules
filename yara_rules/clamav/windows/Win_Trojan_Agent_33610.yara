rule Win_Trojan_Agent_33610
{
strings:
	$a0 = { 709840eb3c16ba0b25a8c36af6abd20c8b5dce939310b3a5b1a0c3607aa6f0aa0121cd327908b139a62e3abe6694859de17cc4595a0c3bb1769123dcd0fdcbfcd2346e58aedae06c54b1c746ab4aca36ff6d7296afd0b0c57ec3514de45f1c3aaaf7f0aadd1378b728184898 }

condition:
	$a0
}

        
