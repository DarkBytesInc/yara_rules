rule Win_Trojan_Lmir_134
{
strings:
	$a0 = { c5e3a82e346dda642e87bdb8087e927195ed090ea4a1ec0c9413d999b8ab36abf085bfe81d87c0326144cfde87ad9f630cd42cec97f8b8c20ba9a3cd532156ee412971dfc459ae53dfc99e340c6beaf0d75a601d45db56a320e72ea5797e2567d70d9f657037a1e2a3c059391563545ef958094c5886c7c2b173c2f1a44dcb2919dade8759a03342a6e91eb62296737fd4caee4f }

condition:
	$a0
}

        