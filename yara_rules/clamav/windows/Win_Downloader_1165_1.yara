rule Win_Downloader_1165_1
{
strings:
	$a0 = { 657b7cdb28dce2358d7d84410945e26c70acc0bdce16e2feb4059308a2e6bd6281384f4ce06da655a422e469767e766b0178aa5e8584b676d2e2b96ed5f47bcd5f858afe1acde5828204b076037da8fce28fa2b14d89f8eeca79dbf2 }

condition:
	$a0
}

        
