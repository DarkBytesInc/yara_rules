rule Win_Downloader_Banload_815
{
strings:
	$a0 = { 1140aa04cb275e67a3a730fdfafda8528f185ebdd258aa77daa6ee962336f3cd204b7bd9ac54ca7224f191e8d3d6733466229cf492952d6ad71247ce02ba53d4e8a3d63f722e121b08c5ae8f1d91ebaafc11ebac6743ce10bc79ab5ece98f8eb8756ace1 }

condition:
	$a0
}

        
