rule Win_Trojan_Stealer_1
{
strings:
	$a0 = { 5633f6687c300010566a02ff15082000105656566a0650ff150c2000108b0850890d04500010ff151020001085c0750c5656685c300010e85e01000056ff35e432001068361000106a02ff15502100106a01a300500010585ec3 }

condition:
	$a0
}

        