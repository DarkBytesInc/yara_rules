rule Win_Trojan_Amitis_30
{
strings:
	$a0 = { 43154dc7c6289139975b3efb12ab6cf43e547859c2227a9cede16963277c2a14fcb60e3df9f5edbcf3bb01ff4177ad3481aafda5dfbefa769036dfeef8e1060bc085570f7f822da19ceb24c0544a06854fab95ca3694a95730b6532cf5d943dc8c9a228cc0df5ed659 }

condition:
	$a0
}

        
