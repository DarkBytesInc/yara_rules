rule Win_Trojan_Agent_33002
{
strings:
	$a0 = { 683c214000e816020000685721400050e8050200006840a841006a01ffd06a066a016a02e839020000a30caf4100eb23 }

condition:
	$a0
}

        