rule Win_Spyware_Banker_688
{
strings:
	$a0 = { 901bef43359ed34b93fe17bcf39115a2147db72f82aa0beb811c55fca9a284269492b08c56439196e3f9c05b395265c29f006ce34c149d84c36baf4691ac885d832234aadeae88d15e573ecebb30f9a40dc8cf8a1cc0e260e938a02d3588e517c353da5ea56409522f88a94b8b12eaab012c0702d4467b605e86ead57ec6a273519d7914f92adcd7b7fb52ef26072bc6183da50bb336 }

condition:
	$a0
}

        