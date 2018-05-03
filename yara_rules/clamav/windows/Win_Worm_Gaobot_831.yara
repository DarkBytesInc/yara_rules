rule Win_Worm_Gaobot_831
{
strings:
	$a0 = { 24ce10209cf09862dd1f7f610bb7dd8878eaa7a8a3482bbf35dbfb2a0e80c35562dde8be38da75bcbb7708620c7fe20cdbe189a2af0063fe0af66312ae6135f610be4b63ae8b3e3b6bcbe02ad02f476312ec00b6a3f6eafb13f73b0eec8096f75d187c275f327588c93d5305f2 }

condition:
	$a0
}

        
