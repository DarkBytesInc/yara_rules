rule Win_Trojan_Agent_32895
{
strings:
	$a0 = { 341cb1df6e1d336dd6d90b78adc03c94d6e329a6a6f930cf6fb42f6e52d61276bfcb3cf96928b3472e3a1ba907111839950e19f9a7feebbe7767775366fbbbe8eae506532ddaa7d15cd392d32c388f09b3290bb936 }

condition:
	$a0
}

        
