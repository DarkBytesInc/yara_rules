rule Win_Trojan_Kates_76
{
strings:
	$a0 = { 01c0d1e8c38d4000c38d40009090c390558bec33c055683510400064ff30648920ff050070400033c05a5959648910683c104000c3e9ceffffffebf85dc38bc0832d0070400001c3558bec33c055686d10400064ff30648920ff050470400033c05a59596489106874104000c3e996ffffffebf85dc38bc0832d0470400001c3ff2564a040008bc0ff2560a040008bc0ff255ca040008bc0ff2558a040008bc0ff2554a040008bc0ff2550a040008bc0ff2570a040008bc0ff256ca040008bc0ff258ca040008bc0ff2588a040008bc0ff2584a040008bc0ff2580a040008bc0ff257ca040008bc0ff2578a040008bc0558bec33c055681511400064ff30648920ff050870400033c05a5959648910681c114000c3e9eefeffffebf85dc38bc0832d0870400001c39090be5ae76a1a5166cab6aefd0a1279b686c3c94ee2559bed7a3a6ff6f6d56a3a328682562a709ca896e4de }

condition:
	$a0
}

        