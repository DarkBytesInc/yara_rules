rule Win_Trojan_SdBot_2340
{
strings:
	$a0 = { 8ee12fe16d4ceb831bc6a9d6ab9e796d27502a5ee17d1f5e8a0c140595c74467768df184b7a4739fceb47aa0dd87b3ae8f9753e640287260f602e7e6d3a45795ba1855855dab6f6516e7e757a41b89d9b0681199445c61971e3a4bbf56e0b04632 }

condition:
	$a0
}

        