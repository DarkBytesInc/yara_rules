rule Win_Downloader_Delf_969
{
strings:
	$a0 = { 1d8cc73e917e042a6008ee2f3119541f2099dc14b3154752e3c1d055f6ac736b737947156629aeed35e4aa55596caabc6b6219d472e583b12bbc0b689a2fc814144a24a0f29a }

condition:
	$a0
}

        
