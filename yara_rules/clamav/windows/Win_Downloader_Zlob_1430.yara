rule Win_Downloader_Zlob_1430
{
strings:
	$a0 = { 6fd962f98979241e116ed352af3ff6a419352b52a2be4575252a5695c27604f9eb3ab35add64df2acceeed52db22daa3a3d902511c22bcabffd77804426a1b5cb5e6739afdae3c901804f24fd24b281fd624c9009f5fbeab9eb331e966faa56dfc59a3a67f5e4929 }

condition:
	$a0
}

        
