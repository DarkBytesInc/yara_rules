rule Win_Downloader_Small_3307
{
strings:
	$a0 = { 195395bb04e23c2045875a96ffd53476bc5fd87bf9b52723d1ecffc295bd8bbdadb84b30a5af9f0e4a0ac3f63e6ad157edcbdb5d6dd72020a3e2666d7e2c682783677f0988936535d114e458d764651df4948bf355dd998191ca }

condition:
	$a0
}

        
