rule Win_Trojan_Hupigon_216
{
strings:
	$a0 = { c0328aebde89f958e756fc998c6f579fe1f331fb4b573efae72c56d9ff9c02fe809f13b899a2bef90a98c8efa6114bc7361dea4428dbef03e8cc917a7c5a1525f1d27f232d01d92c524cbf9b565d1aabd80c1e4615d8a1149f8a17be1b911f648297ea4d67cdba575aeb96e5c742 }

condition:
	$a0
}

        
