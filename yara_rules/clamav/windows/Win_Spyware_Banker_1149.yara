rule Win_Spyware_Banker_1149
{
strings:
	$a0 = { d01a82e7e8b4d2aee94d35ca38e75d0b739cefd66f40dd263e7fb12ca32345bab92e508165b6480f4b22c7fd368d2da0347c0f6e0946c1230daa3a46ec3930eee4ebe11a0b7db819e1a57b414e38eb5418c5bb50f73b066ddc1a }

condition:
	$a0
}

        
