rule Win_Trojan_Lineage_117
{
strings:
	$a0 = { 9369d86072397a39ba8635b8af288303fd90ef090b120b3e0257d14222cff49617cd376eaa5eb1e456652d97ed82e681268a035b8c26ef680c416db71bfeacd78ed967c8762c9e4f6ec5b8b08e65444c696b3cff47d2320669d84c1947fb14b140625807 }

condition:
	$a0
}

        