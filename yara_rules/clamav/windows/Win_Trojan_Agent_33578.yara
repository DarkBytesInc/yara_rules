rule Win_Trojan_Agent_33578
{
strings:
	$a0 = { bb0ebcc14bfa4a29f08a57989189dc53fc701580a85475325ed6451dc5cc013d003cfc846746f4c24462534cd69f67f131fa7de4243a60388cdfcceeffcdc578d12e291459fdbaed8ab0341d10901d92d735 }

condition:
	$a0
}

        
