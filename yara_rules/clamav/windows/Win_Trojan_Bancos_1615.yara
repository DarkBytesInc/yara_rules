rule Win_Trojan_Bancos_1615
{
strings:
	$a0 = { c4ca810e643914351d4ff7699c29ef358aaecb7025bfa77683b1864fa1a67bebd6e61f03c36ef781b82e9971fda5d16f12cbf154aea77fc65f6d60cfe88d97e01d44f13000f69b32851126151db9181b7d56dda3a3b91f4e65be94c6dd9ba1bbc50db7cb7e50090c9ea03098e992a2677c7e240b4d72ef166caef591532d40940dfc8a6f27a5e01df6d31768e3d960dc }

condition:
	$a0
}

        