rule Win_Spyware_Banker_1902
{
strings:
	$a0 = { f956597236a7132fa0cbba52aa93be8efbb58d4377745374214b7b4f9cbb24e3253fd4e54497b223b87b00c7ee4b0906b1e2220e4c37f8cd03961109b501fb72b4a3c76178113156f980f0945a07aa3a97ff049dbd2b756fd24362ee6c4a141bfad6a1ad9fbe01f9d8045d5fe31dea44ab85b1eada1788acf24f326a659edec880531fa7de3f6e14d8382c80ec61bb8945f88fe0a3de }

condition:
	$a0
}

        