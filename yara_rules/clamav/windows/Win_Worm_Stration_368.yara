rule Win_Worm_Stration_368
{
strings:
	$a0 = { ccda0c19a1bc92e65e7d223d8cca97eb359ee7981f4f14df8d56ccc8dadd37335906b42a9585c13cdb000647071ea460e1758ec1e2cad2c6f68646deef6db04dd09d5a8d303f5eb7dffd1b9a63ce2ea7592f9fc8dee61c2e55686b767c62a24f }

condition:
	$a0
}

        
