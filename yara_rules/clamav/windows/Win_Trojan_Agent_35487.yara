rule Win_Trojan_Agent_35487
{
strings:
	$a0 = { 82126fff41307c3b893876f34059771c1657f3a76d05ab867dd0fabc7f08a879e79994a6445f06789431e9b1f3da4a47e1f0d23fed746af9bf595613502750e52e55c3bc8bbfe375b81bb1a69d329998877c86d423196b5a757c502d3dcdb761564bf17f6086714a63688b56e555221fb769668bf9ec1ae3b056f8ee03dabf4de836d9959644d9aa3aea158a }

condition:
	$a0
}

        