rule Win_Worm_Stration_453
{
strings:
	$a0 = { 339816a83cbad0adcef0be0b2b6bb366b2bb6319625bef6b3e37ce673b9cc97c839fde254f42c36146784a4cae858b6227345c3b02083abbbc52a33cff3a7174c926fdcc4b97b5885cc09b60e3c08a326f0ce933e8b4ff08a0dfbd8c55aacf296e47e95d9ccd31ad916dddef1a090c0c117d0648b717d09f78efb67f58ef32a143da6da5807ac47b34ccb623736141 }

condition:
	$a0
}

        