rule Win_Downloader_932_1
{
strings:
	$a0 = { b14aefe1e1c8a2235b63c043f2e4eac37a2ebcafd0d83da8d2fee9d964b6ad66770cd127d3fe181e44105bd7cdd9031487dfa3d642362816c4b5d1ddfbe290385babcc92d5d69e5c28bdcd7bfc01d1feb2eca3bf73120022fe05a324 }

condition:
	$a0
}

        
