rule Win_Trojan_Mybot_4960
{
strings:
	$a0 = { 7f50b9a111ab68eb16b8003ac5f029c751876aa698bea9ba2a37d985eb842c59f19f22e6217a02816a08a78f486df97095e27b0f8be17a0a0eef17792e39d8fdfdafc13136f4c3340516ae18a43f }

condition:
	$a0
}

        
