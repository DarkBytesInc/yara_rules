rule Win_Downloader_Agent_35033
{
strings:
	$a0 = { a1b5ffbda3e7f2ff12c167eb5ac237a4c03af2a6200e3ccb16c70f59eb0e3d9120c4f05def571f9420c0fc2ee0c168c574ea2052e4ccef54efca68c4755bfa57f9d6672b395be6a416c15d3027fda84cef19e15eff3f77f622fe0b5e21df }

condition:
	$a0
}

        
