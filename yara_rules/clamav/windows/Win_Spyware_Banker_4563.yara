rule Win_Spyware_Banker_4563
{
strings:
	$a0 = { ff3cd180ba23fcebff1be86f364b80413ac47a66103c2550a1e0facf968faaa94fee7233364313d56b865b13fba587453351b630dcb72d3780e5b222a526bbcadabc5e8ed4ec9af625b78e8f14d0db1366b000261e47effc7fb5a778c051eca521588ab5 }

condition:
	$a0
}

        
