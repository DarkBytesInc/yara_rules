rule Win_Downloader_Agent_32297
{
strings:
	$a0 = { d408805c75ac801c4bc103b8ed2688d968e71e0b922cb544e70b47b572ec83685677196fc7e2a6f690a54eb6f98373f134bc676479d813c6eae28484f04804b992142e77b101471c082af45fee8bed6c5b58a06317373ceeb38246e86436348f7d16dbc20c9b2dc85c0ec98276c5c9382fb5b1ec04350087784dc40375af1e0a6d622ed0c441a8eaeab3beee7661c8d625b6c0ea }

condition:
	$a0
}

        