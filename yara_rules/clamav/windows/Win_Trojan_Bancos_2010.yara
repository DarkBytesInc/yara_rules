rule Win_Trojan_Bancos_2010
{
strings:
	$a0 = { 2632e36921de64c25b6d173f3eeeb2333c96455ca913d65b23f57a7fa39932fa6fa0084ffa7bbd863d165b63b9fb50bdbb585ed658d933ce3027827fbea1ea07c301a974892f220264dc39462b8ba6cffbdb0a4d8fa23a055d3f8fc0a856a85929aae7174c739f1990cf7241fcdd }

condition:
	$a0
}

        