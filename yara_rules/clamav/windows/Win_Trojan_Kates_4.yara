rule Win_Trojan_Kates_4
{
strings:
	$a0 = { c38d4000c38d400031d2c390558bec33c055683110400064ff30648920ff050090400033c05a59596489106838104000c3e9ceffffffebf85dc38bc0832d0090400001c3558bec33c055686910400064ff30648920ff050490400033c05a59596489106870104000c3e996ffffffebf85dc38bc0832d0490400001c3ff2590a040008bc0ff258ca040008bc0ff2588a040008bc0ff2584a040008bc0ff2580a040008bc0ff257ca040008bc0ff2578a040008bc0ff2574a040008bc0ff2570a040008bc0ff256ca040008bc0ff2568a040008bc0ff2564a040008bc0ff2560a040008bc0ff255ca040008bc0ff2558a040008bc0ff2554a040008bc0ff2550a040008bc0ff254ca040008bc0ff2548a040008bc0ff2544a040008bc0ff2540a040008bc0ff253ca040008bc0ff25b0a040008bc0ff25aca040008bc0ff25a8a040008bc0ff25a4a040008bc0ff25a0a040008bc0 }

condition:
	$a0
}

        