rule Win_Trojan_Agent_33381
{
strings:
	$a0 = { feea1003ed441496a128a39057c5cda866244a48413c0fa9ff8508aa35785f648595f4e00a675c311dcf6defd1c9bb61cff23d908cc17c944a8263b930d16216d2b1bebcf11ff0017700d152b074b8cab054bcdd63bc5ff1c70d2de7 }

condition:
	$a0
}

        
