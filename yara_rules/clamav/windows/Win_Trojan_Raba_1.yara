rule Win_Trojan_Raba_1
{
strings:
	$a0 = { 636f707920253020222a73686172652a5c637261636b414d2e62617422203e206e756c }
	$a1 = { 6e65742073656e642025636f6d70757465726e616d652520596f752061726520696e6665637465642077697468204e6574576f726d21203e206e756c }

condition:
	$a0 and $a1
}

        